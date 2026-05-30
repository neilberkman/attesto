defmodule Attesto.RefreshStoreETSContractTest do
  @moduledoc false
  # Runs the shared `Attesto.RefreshStore` contract against the ETS
  # reference implementation. async: false because
  # `Attesto.RefreshStore.ETS` is a named singleton GenServer; the contract
  # `setup` starts it via start_supervised!.
  use ExUnit.Case, async: false
  use Attesto.RefreshStoreContract, store: Attesto.RefreshStore.ETS
end
