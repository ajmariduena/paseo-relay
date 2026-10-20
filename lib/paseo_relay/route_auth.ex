defmodule PaseoRelay.RouteAuth do
  @moduledoc false

  alias PaseoRelay.Connection

  def challenge(%Connection{version: 3, role: :server}) do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :x25519)
    nonce = :crypto.strong_rand_bytes(32)

    message = %{
      type: "relay_auth_challenge",
      key: Base.encode64(public_key),
      nonce: Base.encode64(nonce)
    }

    {Jason.encode!(message), {private_key, nonce}}
  end

  def verify(%Connection{version: 3, role: :server} = connection, {private_key, nonce}, payload) do
    with {:ok, %{"type" => "relay_auth_response", "proof" => encoded_proof}} <-
           Jason.decode(payload),
         {:ok, proof} <- canonical_proof(encoded_proof),
         {:ok, public_key} <- Base.decode64(connection.daemon_key),
         shared <- :crypto.compute_key(:ecdh, public_key, private_key, :x25519),
         false <- shared == <<0::256>>,
         message <-
           Jason.encode!([
             "paseo-relay-v3",
             connection.server_id,
             connection.connection_id,
             Base.encode64(nonce)
           ]),
         expected <- :crypto.mac(:hmac, :sha256, shared, message) do
      :crypto.hash_equals(expected, proof)
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  defp canonical_proof(encoded) when is_binary(encoded) do
    with {:ok, proof} <- Base.decode64(encoded),
         32 <- byte_size(proof),
         ^encoded <- Base.encode64(proof) do
      {:ok, proof}
    else
      _ -> :error
    end
  end

  defp canonical_proof(_), do: :error
end
