import formencode


# these should be tuples of ('Short', 'Long')


info_AcmeChallengeUnknownPolls = [
    "AcmeChallengeUnknownPoll",
    "A challenge which has been polled, but not set up",
]
info_AcmeOrders = [
    "A LetsEncrypt ACME Order",
    "An ACME order is essentially a Certificate Signing Request.",
]
info_AcmeAccountKeys = [
    "Used to make Acme Orders",
    "AcmeAccountKeys identify our account to LetsEncrypt's ACME server.",
]
info_PrivateKeys = [
    "PrivateKeys sign CertificateRequests and ServerCertificates",
    "PrivateKeys are paired to our Certifcate Requests.",
]
info_CACertificates = [
    "Official LetsEncrypt",
    "CACertificates are `Certificate Authority Certificates`, or what LetsEncrypt uses to sign our ServerCertificates.",
]
info_CACertificateProbes = [
    "Probe Events",
    "Probe the LE website to find new published Certificate Authority Certificates (if any) and update our database.",
]


info_Domains = [
    "Domains we manage certificates for.",
    "Domains we manage certificates for.",
]
info_CertificateRequests = [
    "Certificate Requests pending and past.",
    "Certificate Requests pending and past.",
]
info_ServerCertificates = [
    "Issued Certificates we manage.",
    "Issued Certificates we manage.",
]
info_UniqueFQDNs = [
    "LetsEncrypt ratelimits the exact set of FQDNs",
    "The LetsEncrypt Authority has ratelimits covering the exact set of FQDNs appearing on a certificate.  You can only reissue these certificates a set number of times per week; you would need to add/remove certificates so they are slightly different in order to bypass this ratelimit",
]


info_AcmeOrderless_new = [
    "ACME-Orderless lets you manage the well-known placements only.",
    "ACME-Orderless lets you manage the well-known placements only.",
]
info_AcmeOrder_new_Automated = [
    "ACME-Automated automates the entire certifcate request process.",
    "ACME-Automated automates the entire certifcate request process.",
]

info_UploadAccountKey = [
    "If you need to upload a LetEncrypt Account key for issuance.",
    "",
]
info_UploadPrivateKey = ["If you need to upload a PrivateKey for signing.", ""]
info_UploadExistingCertificate = [
    "Upload for management. Requires: `cert.pem`, `chain.pem`, `privkey.pem`",
    "This requires: `cert.pem`, `chain.pem`, `privkey.pem`.",
]
info_UploadCACertificate = [
    "Upload a trusted cerficate.  This is the `chain.pem`",
    "This requires: `chain.pem`",
]
