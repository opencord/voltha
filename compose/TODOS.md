## Next Steps Planned

- [DONE] Adding health-check to voltha (and consul)
- [Z] Adding membership tracking
- [Z] Adding leader election
- [Z] Work out a load sharding mechanism

- [N] Add flake8 support (make or part of build)
- [N] Coverage support and have coverage report hooked up to make

- [Z] Add documentation for the existing docker-compose based system
- [?] Add system test for the above

- [N] Move in the openflow (lexi) code base
- [N] Move in the EOAM and/or Tibit TAL
- [N] Decide where olt-oftest should live: keep as external package
      or replicate

- [N] make system-test:
  - fire up a docker ensable using docker-compose
  - optionally configure network access to device(s)
  - make sure olt-ofagent test code is available
  - execute relevant test(s)

- Mock adapter


## Next hackaton

- [?] Flash out internal APIs


## Architectural questions

- Place a set of internal queues between the layers, or just use
  direct Twisted async calls
- Primary data format for internal abstract API in/out data:
  - Type-specific Python classes with self-contained schema enforcement
  - "JSON data" == nested Python OrederDict; schema enforcement is
    implemented in key points in the architecture


