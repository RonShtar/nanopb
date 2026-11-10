@echo off
:: protoc plugin launcher for validate\nanopb_validate\filters.py (Windows).
::
::   protoc --plugin=protoc-gen-nanopb-validate=validate\nanopb_validate\plugin\protoc-gen-nanopb-validate.bat ^
::          --nanopb_out=--protoc-insertion-points:DIR --nanopb-validate_out=DIR foo.proto
::
:: --nanopb_out must come first: this plugin inserts into the files nanopb
:: generates, and protoc runs generators in command line order. The
:: "python -m nanopb_validate gen" command does all of this for you.

set mydir=%~dp0
python "%mydir%..\filters.py" %*
