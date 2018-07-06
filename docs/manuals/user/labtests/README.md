# Overview

## Purpose

The purpose of this section is to assist in potential lab testing of Voltha and Voltha-certified PON hardware solutions.

## Approach and Outline

Test exercises are currently grouped based on scope. Although a few tests require nothing more than a single Linux server, most tests require a hardware installation, a "test POD," available.

Specifically, we structure the test process as follows:

* [Test POD and requirements](requirements.md)
* [Preparations](preparations.md)
* [Voltha deployment and related readiness tests](V00_voltha.md)
* [Voltha operating on a software simulated PON network ("ponsim")](S00_ponsim_tests.md) (optional) this is useful if no real PON hardware is available and it provides a dataplane capable PON network which is simulated in software
* [Voltha working with Broadcom Maple based OLT and Broadcom ONU(s)](M00_maple_olt_tests.md)
* [Voltha working with Tibit MicroOLT and certified ONUs](T00_tibit_olt_tests.md)
* [Additional tests show-casing upcoming features of Voltha based PON solutions](P00_previews.md)

## Recommended Test Method

Most of the activation steps desribed in the test procedure can be directly copy-pasted from the test document to the respecive test terminal window.

For best outcome, we recommend bringing up this test documentation on-line. There are two ways of doing that:

* In a PDF document viewer
* (Recommended) In a Web browser in gitbook reading mode. To do this, you need access to the HTML-compiled version of this gitbook document. You can easily do it on a Voltha development host, following these steps:

```shell
cd $VOLTHA_BASE
cd docs
make serve
```

This will build the documentation into an HTML dir structure and will start serving it up on the <http://localhost:4000> URL.

If you need remote access from the browser to the server where the doc is generated, Ctrl-C the *make serve* line, and instead do as follows:

```shell
cd _book
python -m SimpleHTTPServer.py 4000
```

You shall now be able to reach the docs using the <http://localhost:4000> URL.
