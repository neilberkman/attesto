defmodule Attesto.Test.PythonBridge do
  @moduledoc """
  In-process Python interpreter bridge for the cross-language parity tests.

  Starts the `erlang_python` runtime in `:owngil` mode (required for the
  Python "Own GIL" / free-threading builds `erlang_python` 3.0 bundles;
  subinterpreter mode does not work against those today) and evaluates
  expressions against it via the `:py` NIF. Test-support only - never part
  of the shipped library (the package's `files` list ships `lib` only).

  The parity tests use this to drive a real reference Python stack
  (`joserfc`, `cryptography`) and confirm Attesto's tokens, thumbprints,
  and DPoP proofs are RFC-conformant wire, not a private dialect. The Python
  helpers live in `test/support/python/attesto_compat.py`; a test adds that
  directory to `sys.path` and calls into it, e.g.

      Attesto.Test.PythonBridge.eval_wrapped!(
        "__import__('attesto_compat').joserfc_verify_rs256(token, pem)",
        %{"token" => jwt, "pem" => public_pem},
        paths: [python_lib_path]
      )

  ## Required packages

  The active interpreter (the one `erlang_python`'s NIF loads) must have
  these importable: `joserfc`, `cryptography`. Install against that
  interpreter (no venv):

      pip install joserfc cryptography

  `available?/0` reports whether the runtime starts and the packages
  import, so a parity module can skip cleanly on a machine without the
  Python stack rather than failing the suite.
  """

  @compile {:no_warn_undefined, [:py]}

  @required_packages ~w(joserfc cryptography)

  @doc "The pip packages the parity tests need importable in the active interpreter."
  @spec required_packages() :: [binary()]
  def required_packages, do: @required_packages

  @doc """
  Start the `erlang_python` runtime in `:owngil` mode if not already
  started. Idempotent. Raises with the failure reason on startup failure.
  """
  @spec ensure_started!() :: :ok
  def ensure_started! do
    {:ok, _} = Application.ensure_all_started(:erlang_python)

    if not :py.contexts_started() do
      case :py.start_contexts(%{mode: :owngil}) do
        {:ok, _contexts} ->
          :ok

        {:error, reason} ->
          raise "Failed to start erlang_python contexts (mode :owngil): #{inspect(reason)}"
      end
    end

    :ok
  end

  @doc """
  Evaluate a Python expression with the given bindings, raising on a Python
  error so a failure surfaces as a real test failure rather than a
  silently-ignored `{:error, _}`.
  """
  @spec eval!(binary(), map()) :: term()
  def eval!(expr, bindings \\ %{}) when is_binary(expr) and is_map(bindings) do
    ensure_started!()

    case :py.eval(expr, bindings) do
      {:ok, result} -> result
      {:error, {type, msg}} -> raise "Python error (#{type}): #{msg}"
      {:error, reason} -> raise "Python error: #{inspect(reason)}"
    end
  end

  @doc """
  Evaluate `expr` after prepending `:paths` onto `sys.path`. Options:

    * `:paths` - absolute directories to prepend to `sys.path` (deduped;
      already-present entries are skipped).

  The setup expressions and the user expression run on the SAME eval frame
  (composed as a tuple-indexing expression) so the user expression's
  free-variable lookups against the eval `locals` stay intact and the
  `sys.path` mutation is visible regardless of which context dispatches.
  """
  @spec eval_wrapped!(binary(), map(), keyword()) :: term()
  def eval_wrapped!(expr, bindings \\ %{}, opts \\ []) when is_binary(expr) and is_map(bindings) and is_list(opts) do
    eval!(wrap(expr, opts), bindings)
  end

  @doc false
  @spec wrap(binary(), keyword()) :: binary()
  def wrap(expr, opts \\ []) when is_binary(expr) and is_list(opts) do
    paths =
      opts
      |> Keyword.get(:paths, [])
      |> validate_paths!()
      |> Enum.uniq()

    setup =
      Enum.map(paths, fn path ->
        "(None if #{inspect(path)} in __import__('sys').path else " <>
          "__import__('sys').path.insert(0, #{inspect(path)}))"
      end)

    case setup do
      [] -> expr
      _ -> "(#{Enum.join(setup, ", ")}, (#{expr}),)[-1]"
    end
  end

  defp validate_paths!(paths) when is_list(paths) do
    Enum.map(paths, fn
      path when is_binary(path) ->
        if File.dir?(path) do
          path
        else
          raise ArgumentError,
                "#{inspect(__MODULE__)}: :paths entry does not exist or is not a directory: #{inspect(path)}"
        end

      other ->
        raise ArgumentError,
              "#{inspect(__MODULE__)}: :paths entries must be binary filesystem paths; got #{inspect(other)}"
    end)
  end

  @doc """
  Whether the bridge can run: the runtime starts and every package in
  `required_packages/0` imports in the active interpreter. Returns
  `{:ok}` on success or `{:skip, reason}` so a parity module can self-skip
  on a machine without the Python stack.
  """
  @spec availability() :: :ok | {:skip, binary()}
  def availability do
    ensure_started!()

    missing =
      Enum.filter(@required_packages, fn pkg ->
        case :py.eval("__import__('importlib.util').util.find_spec(#{inspect(pkg)}) is not None", %{}) do
          {:ok, true} -> false
          _ -> true
        end
      end)

    case missing do
      [] -> :ok
      _ -> {:skip, "missing Python package(s): #{Enum.join(missing, ", ")} (pip install #{Enum.join(missing, " ")})"}
    end
  rescue
    e -> {:skip, "erlang_python unavailable: #{Exception.message(e)}"}
  catch
    kind, reason -> {:skip, "erlang_python unavailable: #{inspect(kind)} #{inspect(reason)}"}
  end
end
