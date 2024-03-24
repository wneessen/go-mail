<!--
SPDX-FileCopyrightText: 2022-2023 The go-mail Authors

SPDX-License-Identifier: CC0-1.0
-->

# go-mail - Easy to use, yet comprehensive library for sending mails with Go

[![GoDoc](https://godoc.org/github.com/wneessen/go-mail?status.svg)](https://pkg.go.dev/github.com/wneessen/go-mail)
[![codecov](https://codecov.io/gh/wneessen/go-mail/branch/main/graph/badge.svg?token=37KWJV03MR)](https://codecov.io/gh/wneessen/go-mail) 
[![Go Report Card](https://goreportcard.com/badge/github.com/wneessen/go-mail)](https://goreportcard.com/report/github.com/wneessen/go-mail) 
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/avelino/awesome-go)
[![#go-mail on Discord](https://img.shields.io/badge/Discord-%23go%E2%80%93mail-blue.svg)](https://discord.gg/ysQXkaccXk) 
[![REUSE status](https://api.reuse.software/badge/github.com/wneessen/go-mail)](https://api.reuse.software/info/github.com/wneessen/go-mail)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8701/badge)](https://www.bestpractices.dev/projects/8701)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/wneessen/go-mail/badge)](https://securityscorecards.dev/viewer/?uri=github.com/wneessen/go-mail)
<a href="https://ko-fi.com/D1D24V9IX"><img src="https://uploads-ssl.webflow.com/5c14e387dab576fe667689cf/5cbed8a4ae2b88347c06c923_BuyMeACoffee_blue.png" height="20" alt="buy ma a coffee"></a>

<p align="center"><img src="./assets/gopher2.svg" width="250" alt="go-mail logo"/></p>

The main idea of this library was to provide a simple interface to sending mails for
my [JS-Mailer](https://github.com/wneessen/js-mailer) project. It quickly evolved into a full-fledged mail library.

go-mail follows idiomatic Go style and best practice. It's only dependency is the Go Standard Library. It combines a lot
of functionality from the standard library to give easy and convenient access to mail and SMTP related tasks.

Parts of this library (especially some parts of [msgwriter.go](msgwriter.go)) have been forked/ported from the
[go-mail/mail](https://github.com/go-mail/mail) respectively [go-gomail/gomail](https://github.com/go-gomail/gomail)
which both seems to not be maintained anymore.

The smtp package of go-mail is forked from the original Go stdlib's `net/smtp` and then extended by the go-mail
team.

## Features

Some of the features of this library:

* [X] Only Standard Library dependant
* [X] Modern, idiomatic Go
* [X] Sane and secure defaults
* [X] Explicit SSL/TLS support
* [X] Implicit StartTLS support with different policies
* [X] Makes use of contexts for a better control flow and timeout/cancelation handling
* [X] SMTP Auth support (LOGIN, PLAIN, CRAM-MD, XOAUTH2)
* [X] RFC5322 compliant mail address validation
* [X] Support for common mail header field generation (Message-ID, Date, Bulk-Precedence, Priority, etc.)
* [X] Reusing the same SMTP connection to send multiple mails
* [X] Support for attachments and inline embeds (from file system, `io.Reader` or `embed.FS`)
* [X] Support for different encodings
* [X] Middleware support for 3rd-party libraries to alter mail messages
* [X] Support sending mails via a local sendmail command
* [X] Support for requestng MDNs (RFC 8098) and DSNs (RFC 1891)
* [X] DKIM signature support via [go-mail-middlware](https://github.com/wneessen/go-mail-middleware)
* [X] Message object satisfies `io.WriteTo` and `io.Reader` interfaces
* [X] Support for Go's `html/template` and `text/template` (as message body, alternative part or attachment/emebed)
* [X] Output to file support which allows storing mail messages as e. g. `.eml` files to disk to open them in a MUA
* [X] Debug logging of SMTP traffic
* [X] Custom error types for delivery errors
* [X] Custom dial-context functions for more control over the connection (proxing, DNS hooking, etc.)

go-mail works like a programatic email client and provides lots of methods and functionalities you would consider
standard in a MUA.

## Documentation
We aim for good GoDoc documenation in our library which gives you a full API reference. We also provide a more in-depth 
documentation website at [go-mail.dev](https://go-mail.dev)

## Compatibility

Go is growing fast and providing great features with every new release. While we'd love to adopt the latest Go features
into our code, we realize that not everybody using this package can run the latest Go versions. Therefore we try to
implement alternative solutions for Go versions that do not support these features. Yet, the work needed to maintain
the separate versions is not to be underestimated. For that reason, we might retire that code at some point. 
We guarantee that go-mail will always support the last four releases of Go. With two Go releases per year, this gives
the user a timeframe of two years to update to the next or even the latest version of Go.

## Support
We have a support and general discussion channel on Discord. Find us at: [#go-mail](https://discord.gg/dbfQyC4s)

## Middleware
The goal of go-mail is to keep it free from 3rd party dependencies and only focus on things a mail library should
fulfill. Yet, since version v0.2.8 we've added support for middleware on the `Msg` object, allowing 3rd parties to
alter a given mail message to their needs without relying on `go-mail` to support their specific need.

To get our users started with message middleware, we've created a collection of useful middlewares. It can be 
found in a seperate repository: [go-mail-middlware](https://github.com/wneessen/go-mail-middleware).

## Examples

We provide example code in both our GoDocs as well as on our official Website (see [Documentation](#documentation)). For a quick start into go-mail
check out our [Getting started](https://go-mail.dev/getting-started/introduction/) guide.

## Authors/Contributors
go-mail was initially authored and developed by [Winni Neessen](https://github.com/wneessen/).

Big thanks to the following people, for contributing to the go-mail project (either in form of code or by 
reviewing code, writing documenation or helping to translate the website):
* [Christian Vette](https://github.com/cvette)
* [Dhia Gharsallaoui](https://github.com/dhia-gharsallaoui)
* [inliquid](https://github.com/inliquid) 
* [iwittkau](https://github.com/iwittkau)
* [James Elliott](https://github.com/james-d-elliott)
* [Maria Letta](https://github.com/MariaLetta) (designed the go-mail logo)
* [Nicola Murino](https://github.com/drakkan)
* [sters](https://github.com/sters)
