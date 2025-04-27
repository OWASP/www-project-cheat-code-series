---

layout: col-sidebar
title: OWASP Cheat Code Series
tags: example-tag
level: 2
type: documentation
pitch: A very brief, one-line description of your project

---

In an age of AI-generated code, it’s more important than ever to confirm whether new code - or an AI-generated fix - is truly secure. While existing resources like OWASP Cheat Sheets and CWE provide valuable guidance and examples, this project goes a step further by showing exactly how those principles apply in real-world scenarios, using a library of deliberately insecure and secure code samples tested by various attack payloads (e.g. from PayloadsAllTheThings). By aligning with recommendations from the Cheat Sheets Series and organizing everything as pass/fail tests, developers can compare the effectiveness of different remediation approaches, validate their own fixes, and gain truly practical insights. The result is a hands-on resource that complements established best-practice guidance - and acts like a “Stack Overflow” for security fixes - by making vulnerability mitigation both discoverable and verifiable.

### Road Map
A working proof of concept has been created in Java, demonstrating the Path Traversal vulnerability: [https://github.com/Aleks-Ry/cheatcode|https://github.com/Aleks-Ry/cheatcode]
The project will be expanded in several directions:

* Broader vulnerability coverage – Add new examples of both insecure and secure implementations for a wide range of vulnerability types.
* Enhanced test payloads – Increase the variety and sophistication of attack payloads to test the robustness of different fixes.
* Multi-language support – Extend the project to cover multiple programming languages and popular frameworks.

The timeline depends on available contributors and community support. The initial goal is to cover the most common SAST-detectable vulnerabilities within the first year, starting with XXE, Command Injection, and SQL Injection. Overall, this is envisioned as a long-term, multi-year project aimed at becoming a comprehensive and evolving resource for secure coding practices.
