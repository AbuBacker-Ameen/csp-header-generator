.. HashCSP documentation master file, created by
   sphinx-quickstart on Thu May  1 00:29:21 2025.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

HashCSP
===================

HashCSP is a powerful Python tool designed to generate and validate Content Security Policy (CSP) headers for web applications. It helps developers secure their websites by creating comprehensive CSP headers that mitigate risks like Cross-Site Scripting (XSS) by specifying trusted sources for scripts, styles, and other resources.

Key Features
-----------

* **Generate CSP Headers**: Scan local HTML files to generate CSP headers with hashes for inline scripts and styles
* **Validate CSP Headers**: Compare existing CSP headers against scanned resources
* **Remote Site Analysis**: Fetch and analyze remote websites using Playwright
* **Dynamic Content Handling**: Capture dynamically inserted scripts and styles
* **Dynamic DOM Monitoring**: Use MutationObserver to track late-loading scripts and styles during runtime
* **Rich CLI Interface**: Colored output with progress indicators and detailed reporting

Getting Started
-------------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   installation
   quickstart
   configuration
   cli

Features
--------

.. toctree::
   :maxdepth: 2
   :caption: Features

   features/generate
   features/validate
   features/remote-analysis
   features/dynamic-content
   features/dynamic-dom-monitoring
   features/logging

.. API Reference (yet to be implemented)
.. ------------

.. .. toctree::
..    :maxdepth: 2
..    :caption: API Documentation

..    api/core
..    api/commands
..    api/config
..    api/logging

Advanced Topics
-------------

.. toctree::
   :maxdepth: 2
   :caption: Advanced Topics

   advanced/security
   advanced/best-practices
   advanced/customization
   advanced/troubleshooting

Contributing
-----------

.. toctree::
   :maxdepth: 2
   :caption: Development

   contributing
   changelog
   roadmap

Indices and Tables
----------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
