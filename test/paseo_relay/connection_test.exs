defmodule PaseoRelay.ConnectionTest do
  use ExUnit.Case, async: true

  alias PaseoRelay.Connection
  alias PaseoRelay.RouteAuth

  test "v3 isolates a daemon key and gives every client a fresh route id" do
    {public_key, _secret_key} = :crypto.generate_key(:ecdh, :x25519)
    key = Base.encode64(public_key)
    query = %{"serverId" => "srv_test", "v" => "3", "daemonKey" => key}

    assert {:ok, control} = Connection.from_query(Map.put(query, "role", "server"))
    assert control.connection_id == ""
    assert control.route_id == "relay-v3:srv_test:" <> key

    assert {:ok, first} =
             Connection.from_query(
               Map.merge(query, %{"role" => "client", "connectionId" => "chosen"})
             )

    assert {:ok, second} = Connection.from_query(Map.put(query, "role", "client"))
    assert first.route_id == control.route_id
    assert first.connection_id != "chosen"
    assert first.connection_id != second.connection_id
  end

  test "v3 refuses missing and invalid daemon keys before routing" do
    base = %{"serverId" => "srv_test", "v" => "3", "role" => "client"}
    assert {:error, _} = Connection.from_query(base)

    assert {:error, _} =
             Connection.from_query(Map.put(base, "daemonKey", Base.encode64(<<0::256>>)))

    assert {:error, _} = Connection.from_query(Map.put(base, "daemonKey", "not-base64"))
  end

  test "v3 verifies the same X25519 and HMAC proof as the TypeScript daemon" do
    daemon_key = "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk="
    relay_secret = Base.decode64!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
    nonce = Base.decode64!("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=")

    proof =
      ~s({"type":"relay_auth_response","proof":"p88dtEdnWeZG75TYCVNd32Jx6uCjJtYzKjqhAzMij9A="})

    assert {:ok, connection} =
             Connection.from_query(%{
               "serverId" => "srv_test",
               "role" => "server",
               "v" => "3",
               "daemonKey" => daemon_key,
               "connectionId" => "conn_test"
             })

    assert RouteAuth.verify(connection, {relay_secret, nonce}, proof)

    refute RouteAuth.verify(
             %{connection | connection_id: "conn_else"},
             {relay_secret, nonce},
             proof
           )
  end
end
