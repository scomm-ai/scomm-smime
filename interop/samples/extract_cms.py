#!/usr/bin/env python3
"""Pull the CMS out of a saved S/MIME .eml. See README.md.

Usage: extract_cms.py message.eml output/prefix

Writes prefix.cms, and for multipart/signed also prefix.content: the signed part
sliced from the raw file, because re-serializing it would change the bytes the
signature covers.
"""
import email
import email.policy
import sys

CMS_TYPES = {
    "application/pkcs7-mime",
    "application/x-pkcs7-mime",
    "application/pkcs7-signature",
    "application/x-pkcs7-signature",
}


def signed_part(raw, boundary):
    delimiter = b"--" + boundary.encode()
    start = raw.index(delimiter)
    start = raw.index(b"\n", start) + 1
    end = raw.index(delimiter, start)
    # The line break before the next boundary belongs to the boundary.
    if raw[end - 2:end] == b"\r\n":
        end -= 2
    elif raw[end - 1:end] == b"\n":
        end -= 1
    return raw[start:end]


def main():
    source, prefix = sys.argv[1], sys.argv[2]
    raw = open(source, "rb").read()
    message = email.message_from_bytes(raw, policy=email.policy.default)
    cms = next((p for p in message.walk() if p.get_content_type() in CMS_TYPES), None)
    if cms is None:
        sys.exit("no S/MIME part found")
    open(prefix + ".cms", "wb").write(cms.get_payload(decode=True))
    print("wrote", prefix + ".cms")
    if message.get_content_type() == "multipart/signed":
        open(prefix + ".content", "wb").write(signed_part(raw, message.get_boundary()))
        print("wrote", prefix + ".content")


if __name__ == "__main__":
    main()
