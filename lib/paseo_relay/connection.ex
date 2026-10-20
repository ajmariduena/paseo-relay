defmodule PaseoRelay.Connection do
  @max_route_id_bytes 256
  @max_v3_server_id_bytes 64
  @max_v3_connection_id_bytes 128

  @enforce_keys [:server_id, :route_id, :role, :version, :connection_id]
  defstruct [:server_id, :route_id, :daemon_key, :role, :version, :connection_id]

  @type t :: %__MODULE__{
          server_id: String.t(),
          route_id: String.t(),
          daemon_key: String.t() | nil,
          role: :server | :client,
          version: 1 | 2 | 3,
          connection_id: String.t() | nil
        }

  @spec from_query(map()) :: {:ok, t()} | {:error, String.t()}
  def from_query(query) do
    with {:ok, role} <- role(query["role"]),
         {:ok, version} <- version(query["v"]),
         {:ok, server_id} <- server_id(query["serverId"], version),
         {:ok, daemon_key} <- daemon_key(query["daemonKey"], version),
         {:ok, connection_id} <-
           connection_id(version, role, query["connectionId"]) do
      route_id =
        if version == 3, do: "relay-v3:#{server_id}:#{daemon_key}", else: server_id

      {:ok,
       %__MODULE__{
         server_id: server_id,
         route_id: route_id,
         daemon_key: daemon_key,
         role: role,
         version: version,
         connection_id: connection_id
       }}
    end
  end

  defp role("server"), do: {:ok, :server}
  defp role("client"), do: {:ok, :client}
  defp role(_), do: {:error, "Missing or invalid role parameter"}

  defp server_id(value, 3)
       when is_binary(value) and byte_size(value) in 1..@max_v3_server_id_bytes do
    if String.match?(value, ~r/\A[A-Za-z0-9_-]+\z/),
      do: {:ok, value},
      else: {:error, "Invalid serverId"}
  end

  defp server_id(value, _version)
       when is_binary(value) and byte_size(value) in 1..@max_route_id_bytes,
       do: {:ok, value}

  defp server_id(value, _version)
       when is_binary(value) and byte_size(value) > @max_route_id_bytes,
       do: {:error, "serverId is too long"}

  defp server_id(_value, _version), do: {:error, "Missing or invalid serverId parameter"}

  defp daemon_key(_value, version) when version in [1, 2], do: {:ok, nil}

  defp daemon_key(value, 3) do
    if PaseoRelay.HandshakeValidation.valid_public_key?(value),
      do: {:ok, value},
      else: {:error, "Missing or invalid daemonKey parameter"}
  end

  defp version(nil), do: {:ok, 1}

  defp version(value) when is_binary(value) do
    case String.trim(value) do
      "" -> {:ok, 1}
      "1" -> {:ok, 1}
      "2" -> {:ok, 2}
      "3" -> {:ok, 3}
      _ -> {:error, "Invalid v parameter (expected 1, 2, or 3)"}
    end
  end

  defp connection_id(1, _role, _value), do: {:ok, nil}

  defp connection_id(2, role, value) do
    value = if is_binary(value), do: String.trim(value), else: ""

    cond do
      byte_size(value) > @max_route_id_bytes -> {:error, "connectionId is too long"}
      role == :client and value == "" -> {:ok, generated_connection_id()}
      true -> {:ok, value}
    end
  end

  defp connection_id(3, role, value) do
    value = if is_binary(value), do: String.trim(value), else: ""

    cond do
      byte_size(value) > @max_v3_connection_id_bytes ->
        {:error, "connectionId is too long"}

      role == :client ->
        {:ok, generated_connection_id()}

      value == "" or String.match?(value, ~r/\A[A-Za-z0-9_-]+\z/) ->
        {:ok, value}

      true ->
        {:error, "Invalid connectionId"}
    end
  end

  defp generated_connection_id do
    "conn_" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end
end
