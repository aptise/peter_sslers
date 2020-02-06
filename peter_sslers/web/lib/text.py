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
info_AccountKeys = [
    "Used to sign Certificate Requests",
    "AccountKeys identify our account to LetsEncrypt when signing.",
]
info_PrivateKeys = [
    "Private Keys matched to Signed Certificates",
    "PrivateKeys are paired to our Certifcate Requests.",
]
info_CACertificates = [
    "Official LetsEncrypt",
    "CACertificates are what LetsEncrypt uses to sign our Certificates.",
]
info_CACertificateProbes = [
    "Probe Events",
    "Probe the LE website to find new certificates (if any) and update our db.",
]


info_Domains = [
    "Domains we manage certificates for.",
    "Domains we manage certificates for.",
]
info_UniqueFQDNs = [
    "LetsEncrypt ratelimits the exact set of FQDNs",
    "The LetsEncrypt Authority has ratelimits covering the exact set of FQDNs appearing on a certificate.  You can only reissue these certificates a set number of times per week; you would need to add/remove certificates so they are slightly different in order to bypass this ratelimit",
]
info_Certificates = ["Issued Certificates we manage.", "Issued Certificates we manage."]
info_CertificateRequests = [
    "Certificate Requests pending and past.",
    "Certificate Requests pending and past.",
]


info_CertificateRequest_new_AcmeFlow = [
    "ACME-flow lets you manage the well-known placements only.",
    "ACME-flow lets you manage the well-known placements only.",
]
info_CertificateRequest_new_AcmeAutomated = [
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
