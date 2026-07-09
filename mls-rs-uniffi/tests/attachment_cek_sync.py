from mls_rs_uniffi import Client, CipherSuite, generate_signature_keypair, client_config_default, Error

client_config = client_config_default()
alice = Client(b'alice', generate_signature_keypair(CipherSuite.CURVE25519_AES128), client_config)
bob = Client(b'bob', generate_signature_keypair(CipherSuite.CURVE25519_AES128), client_config)

# Alice creates a group and adds Bob.
alice_group = alice.create_group(None)
output = alice_group.add_members([bob.generate_key_package_message()])
alice_group.process_incoming_message(output.commit_message)
bob_group = bob.join_group(None, output.welcome_message).group

# Both members derive the same attachment CEK.
cek_alice = alice_group.attachment_cek(0x8000, b'object-id')
cek_bob = bob_group.attachment_cek(0x8000, b'object-id')

assert cek_alice == cek_bob
assert len(cek_alice) == 32

# The component secret also matches.
assert alice_group.safe_export_secret(0x8000) == bob_group.safe_export_secret(0x8000)

# An empty object id is rejected.
raised = False
try:
    alice_group.attachment_cek(0x8000, b'')
except Error.MlsError:
    raised = True

assert raised
