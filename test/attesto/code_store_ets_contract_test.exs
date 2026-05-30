defmodule Attesto.CodeStoreETSContractTest do
  @moduledoc false
  # Runs the shared `Attesto.CodeStore` contract against the ETS reference
  # implementation. async: false because `Attesto.CodeStore.ETS` is a named
  # singleton GenServer; the contract `setup` starts it via
  # start_supervised!.
  use ExUnit.Case, async: false
  use Attesto.CodeStoreContract, store: Attesto.CodeStore.ETS
end
