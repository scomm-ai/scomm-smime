# Real client samples

The OpenSSL matrix proves standards conformance. These samples prove the engine
works with the clients people use, such as Outlook, Thunderbird and Apple Mail.
There are none yet, because capturing one needs a real mail account and a person
at the client.

`crates/scomm-smime-cms/tests/client_samples.rs` runs every case in
`crates/scomm-smime-cms/tests/fixtures/client-samples/cases.json`. A case is
either expected to work or is a known gap named after its audit finding, and a
gap that starts working fails the run so the list stays true.

Everything committed here is public, including the identity's private key. Use a
mailbox made for testing, never a real person's address or key.

## Capture a sample

1. Make a throwaway identity for the test mailbox:

   ```bash
   interop/samples/make_identity.sh rsa test-mailbox@your-domain.example
   ```

   Use `p256` or `p384` in place of `rsa` for an ECC identity. It writes
   `<name>.p12` (password `interop`), `<name>.crt` and `<name>.p8` to
   `fixtures/client-samples/identities/`.

2. Import the `.p12` into the client and set it as the signing and encryption
   certificate for that mailbox.

3. From the client, send the mailbox one signed message and one encrypted
   message. Use the text `interop sample` as the body.

4. Save each received message as a `.eml` file, then extract its CMS:

   ```bash
   python3 interop/samples/extract_cms.py message.eml crates/scomm-smime-cms/tests/fixtures/client-samples/outlook-2024-signed
   ```

   This writes `<name>.cms`, and for a detached signature also `<name>.content`,
   the exact signed bytes.

5. Add a case to `cases.json`:

   ```json
   [
     {
       "client": "Outlook 2024",
       "name": "AES-256-CBC, RSA",
       "kind": "decrypt",
       "message": "outlook-2024-encrypted.cms",
       "identity": "rsa",
       "alg": "smime-rsa-oaep-sha256",
       "expect": "gap:H1"
     },
     {
       "client": "Outlook 2024",
       "name": "SHA-256, RSA",
       "kind": "verify",
       "message": "outlook-2024-signed.cms",
       "content": "outlook-2024-signed.content",
       "identity": "rsa",
       "alg": "smime-rsa-pss-sha256",
       "expect": "gap:H1"
     }
   ]
   ```

   `expect` is `works` or `gap:<finding>`. Run the test once to see the result,
   then record what it does today.

6. Note in the commit message which client version, operating system and settings
   produced the sample.
