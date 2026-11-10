# Make rules for nanopb validation, next to nanopb's own extra/nanopb.mk.
#
#   NANOPB_DIR = path/to/nanopb
#   include $(NANOPB_DIR)/validate/extra/nanopb_validate.mk   # before nanopb.mk
#   include $(NANOPB_DIR)/extra/nanopb.mk                     # optional
#
#   NANOPB_VALIDATE_OPTS = --filter pkg.Envelope              # optional
#   CSRC += foo.pb.c foo_validate.c $(NANOPB_VALIDATE_CSRC)
#   CFLAGS += $(NANOPB_VALIDATE_CFLAGS)
#
# %.proto -> %.pb.c, %.pb.h, %_validate.c, %_validate.h in one protoc run,
# via `python -m nanopb_validate gen`. Include this file before nanopb.mk:
# make uses the first pattern rule that can build a target, and this one also
# runs the validate plugin.

NANOPB_VALIDATE_DIR ?= $(NANOPB_DIR)/validate
NANOPB_VALIDATE_PYTHON ?= python3
NANOPB_VALIDATE_OPTS ?=

NANOPB_VALIDATE_CSRC = $(NANOPB_VALIDATE_DIR)/runtime/pb_validate.c
NANOPB_VALIDATE_CFLAGS = -I$(NANOPB_DIR) -I$(NANOPB_VALIDATE_DIR)/runtime

%.pb.c %.pb.h %_validate.c %_validate.h: %.proto
	$(NANOPB_VALIDATE_PYTHON) $(NANOPB_VALIDATE_DIR)/nanopb_validate gen $(NANOPB_VALIDATE_OPTS) $<
