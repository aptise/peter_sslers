Rejected Tasks
===============

* UniqueFQDNSet
    Idea
	- allow a set to be decomposed into one or more sets
	- for example:
		- original set: [a.example.com, b.example.com, c.example.com,]
		- new set(s): [a.example.com,]; [b.example.com, c.example.com,]
		- new set(s): [a.example.com,]
    Rejection
    - This is inherently handled through the "/renewal-configuration/{ID}/new-configuration"
* Take into account the validity of existing LetsEncrypt authz and challenges when requesting certs.
    Rejection
    - The cached validity time may drastically change as short-life certs re introduced.
