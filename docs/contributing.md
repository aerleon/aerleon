# Contributing to Aerleon

Thank you for your curiosity on how to contribute! There are many different ways to help out. Please see below for different ways.

## Community Engagement

The easiest way to contribute is to engage with the community. Join our [slack](https://aerleon.slack.com/), make a blog post, join discussions. Getting the project name to people who could use it is one of the most impactful things you can do. If you have ideas on places we should be engaging in ourselves, conferences we should be attending, please let us know!

## Sponsorships

Sponsoring our project is a great opportunity for companies or individuals to show their support for and investment in our community. It shows commitment to collaborating with us and advancing the project. If you would like to sponsor us there are multiple ways in which you can, including but not limited to:

* Monetary: Donating money is the most straightforward way of showing support for the project. It will go towards paying for licenses and fees incurred in running the project, acquiring hardware needed to validate ACLs, or paying for contributor time in supporting the project.
* Hardware: We try to validate our project against hardware, either virtual or physical. If you believe you have hardware that would be helpful for the project to have, please reach out and [contact us](https://github.com/aerleon/aerleon/blob/main/README.md#contact).

## File issues

No one likes bugs, especially us! If you think you found one please file an issue. Be as detailed as possible in your description including example files to replicate the issue. This will help us to expedite a fix as quickly as possible. Even better, submit the fix with the issue! If the issue is possibly a vulnerability, please instead see our [SECURITY.md](https://github.com/aerleon/aerleon/blob/main/SECURITY.md) file instead on how to report.

## Documentation

Writing documentation can sometimes be thankless work. We, however, appreciate it! Whether it is writing an entire new page providing a tutorial, fixing a single typo or anything in between.

## Code contributions

Writing code can include adding new features or fixing issues that have been reported. To get started with contributing code you will want to familiarize yourself with our guidelines and tools.

### Guidelines

* Generally it is best to reach out before writing any significant amount of code. It may be that someone is almost finished with a fix, or maybe an idea needs to be discussed before hand. The best place to reach out would be in a Github issue.
* Tests always need to be included, these are important and cannot be skipped. Good tests make sure we are not accidentally breaking your code in the future.

## Code Style and Formatting

We have adopted [Black](https://github.com/ambv/black) as our code formatter. This takes a lot of guesswork out of formatting our code. The code we forked from adopted the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html) which we still adopt where it does not conflict with Black. Generally this means following the [Language Rules](https://google.github.io/styleguide/pyguide.html#s2-python-language-rules) while ignoring the [Style Rules](https://google.github.io/styleguide/pyguide.html#s3-python-style-rules)

## Testing

```sh
poetry run pytest
```

This will run all tests and provide a report of what tests passed and failed.
