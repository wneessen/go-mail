<!--
SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>

SPDX-License-Identifier: CC0-1.0
-->

# go-mail - Easy to use, yet comprehensive library for sending mails with Go

[![GoDoc](https://godoc.org/github.com/wneessen/go-mail?status.svg)](https://pkg.go.dev/github.com/wneessen/go-mail)
[![codecov](https://codecov.io/gh/wneessen/go-mail/branch/main/graph/badge.svg?token=37KWJV03MR)](https://codecov.io/gh/wneessen/go-mail) 
[![Go Report Card](https://goreportcard.com/badge/github.com/wneessen/go-mail)](https://goreportcard.com/report/github.com/wneessen/go-mail) 
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/avelino/awesome-go) [![#go-mail on Discord](https://img.shields.io/badge/Discord-%23gomail-blue.svg)](https://discord.gg/zSUeBrsFPB) 
[![REUSE status](https://api.reuse.software/badge/github.com/wneessen/go-mail)](https://api.reuse.software/info/github.com/wneessen/go-mail) 
<a href="https://ko-fi.com/D1D24V9IX"><img src="https://uploads-ssl.webflow.com/5c14e387dab576fe667689cf/5cbed8a4ae2b88347c06c923_BuyMeACoffee_blue.png" height="20" alt="buy ma a coffee"></a>

<p align="center"><img src="./assets/gopher2.svg" width="250" alt="go-mail logo"/></p>

The main idea of this library was to provide a simple interface to sending mails for
my [JS-Mailer](https://github.com/wneessen/js-mailer) project. It quickly evolved into a full-fledged mail library.

go-mail follows idiomatic Go style and best practice. It's only dependency is the Go Standard Library. It combines a lot
of functionality from the standard library to give easy and convenient access to mail and SMTP related tasks.

Parts of this library (especially some parts of [msgwriter.go](msgwriter.go)) have been forked/ported from the
[go-mail/mail](https://github.com/go-mail/mail) respectively [go-gomail/gomail](https://github.com/go-gomail/gomail)
which both seems to not be maintained anymore.

## Features

Some of the features of this library:

* [X] Only Standard Library dependant
* [X] Modern, idiomatic Go
* [X] Sane and secure defaults
* [X] Explicit SSL/TLS support
* [X] Implicit StartTLS support with different policies
* [X] Makes use of contexts for a better control flow and timeout/cancelation handling
* [X] SMTP Auth support (LOGIN, PLAIN, CRAM-MD)
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

go-mail works like a programatic email client and provides lots of methods and functionalities you would consider
standard in a MUA.

## Documentation
We aim for good GoDoc documenation in our library which gives you a full API reference. We also provide a more in-depth documentation website at 
[go-mail.dev](https://go-mail.dev)

## Support
We have a support and general discussion channel on the Gophers Discord server. Find us at: [#go-mail](https://discord.gg/zSUeBrsFPB)

## Middleware
The goal of go-mail is to keep it free from 3rd party dependencies and only focus on things a mail library should
fulfill. Yet, since version v0.2.8 we've added support for middleware on the `Msg` object, allowing 3rd parties to
alter a given mail message to their needs without relying on `go-mail` to support their specific need.

To get our users started with message middleware, we've created a collection of useful middlewares. It can be 
found in a seperate repository: [go-mail-middlware](https://github.com/wneessen/go-mail-middleware).

## Examples

We provide example code in both our GoDocs as well as on our official Website (see [Documentation](#documentation)). For a quick start into go-mail
check out our [Getting started](https://go-mail.dev/getting-started/introduction/) guide.

## Contributors
Thanks to the following people for contributing to the go-mail project:
* [Dhia Gharsallaoui](https://github.com/dhia-gharsallaoui)
* [inliquid](https://github.com/inliquid) 
* [Maria Letta](https://github.com/MariaLetta) (designed the go-mail logo)
