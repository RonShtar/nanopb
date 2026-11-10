/* Usage: include in *_validate.c to enable optional filter integration.
 * Auto-detects filter.h (or force with -DPB_FORCE_FILTER / disable with -DPB_FORCE_NO_FILTER / manual -DPB_HAS_FILTER).
 * Mode A: error macros call filter_error_packet_size()/filter_error then return false; check macros log via filter_check_* and yield boolean; PB_LOG_* emits filter_error.
 * Mode B: error macros return false; check macros are pure comparisons; PB_LOG_* no-ops.
 * Macros: PB_ERROR_BUFFER_TOO_SMALL / PB_ERROR_BUFFER_TOO_BIG / PB_CHECK_EQ / PB_CHECK_RANGE / PB_CHECK_MIN / PB_CHECK_MAX / PB_VALIDATE_PACKET_SIZE / PB_LOG_INVALID_OPCODE / PB_LOG_INVALID_HEADER.
 */

#ifndef PB_FILTER_MACROS_H_INCLUDED
#define PB_FILTER_MACROS_H_INCLUDED

#ifdef PB_FORCE_NO_FILTER
#  undef PB_HAS_FILTER
#endif
#ifdef PB_FORCE_FILTER
#  ifndef PB_HAS_FILTER
#    define PB_HAS_FILTER 1
#  endif
#endif

/* Detect filter.h */
#if !defined(PB_HAS_FILTER) && !defined(PB_FORCE_NO_FILTER)
#  if defined(__has_include)
#    if __has_include("filter.h")
#      define PB_HAS_FILTER 1
#    endif
#  endif
#endif
#ifdef PB_HAS_FILTER
#  include "filter.h"
#endif

#ifdef PB_HAS_FILTER
#  define PB_FILTER_CALL_ERROR_PACKET_SIZE(ctx,errstr,packet_size,allowed_size) (void)filter_error_packet_size((ctx),(errstr),(packet_size),(allowed_size))
#  define PB_FILTER_CALL_VALUE(ctx,var,exact) (void)filter_check_value_generic((ctx),(var),(exact))
#  define PB_FILTER_CALL_BOUNDARY(ctx,var,minv,maxv) (void)filter_check_boundary_generic((ctx),(var),(minv),(maxv))
#  define PB_FILTER_CALL_MIN(ctx,var,minv) (void)filter_check_min_generic((ctx),(var),(minv))
#  define PB_FILTER_CALL_MAX(ctx,var,maxv) (void)filter_check_max_generic((ctx),(var),(maxv))
#  define PB_FILTER_CALL_ERROR(ctx,errstr) (void)filter_error((ctx),(errstr))
#else
#  define PB_FILTER_CALL_ERROR_PACKET_SIZE(ctx,errstr,packet_size,allowed_size) ((void)0)
#  define PB_FILTER_CALL_VALUE(ctx,var,exact) ((void)0)
#  define PB_FILTER_CALL_BOUNDARY(ctx,var,minv,maxv) ((void)0)
#  define PB_FILTER_CALL_MIN(ctx,var,minv) ((void)0)
#  define PB_FILTER_CALL_MAX(ctx,var,maxv) ((void)0)
#  define PB_FILTER_CALL_ERROR(ctx,errstr) ((void)0)
#endif

#ifdef PB_HAS_FILTER
#  define PB_ERROR_BUFFER_TOO_SMALL(ctx,struct_size,packet_size) do { PB_FILTER_CALL_ERROR_PACKET_SIZE((ctx),"buffer_too_small",(packet_size),(struct_size)); return false; } while(0)
#  define PB_ERROR_BUFFER_TOO_BIG(ctx,struct_size,packet_size)   do { PB_FILTER_CALL_ERROR_PACKET_SIZE((ctx),"buffer_too_big",(packet_size),(struct_size)); return false; } while(0)
#else
#  define PB_ERROR_BUFFER_TOO_SMALL(ctx,struct_size,packet_size) do { return false; } while(0)
#  define PB_ERROR_BUFFER_TOO_BIG(ctx,struct_size,packet_size)   do { return false; } while(0)
#endif

#ifdef PB_HAS_FILTER
#  define PB_CHECK_EQ(ctx,var,exact)   ( PB_FILTER_CALL_VALUE((ctx),(var),(exact)), ((var) == (exact)) )
#  define PB_CHECK_RANGE(ctx,var,minv,maxv) ( PB_FILTER_CALL_BOUNDARY((ctx),(var),(minv),(maxv)), ((var) >= (minv) && (var) <= (maxv)) )
#  define PB_CHECK_MIN(ctx,var,minv)   ( PB_FILTER_CALL_MIN((ctx),(var),(minv)), ((var) >= (minv)) )
#  define PB_CHECK_MAX(ctx,var,maxv)   ( PB_FILTER_CALL_MAX((ctx),(var),(maxv)), ((var) <= (maxv)) )
#else
#  define PB_CHECK_EQ(ctx,var,exact)   ((var) == (exact))
#  define PB_CHECK_RANGE(ctx,var,minv,maxv) ((var) >= (minv) && (var) <= (maxv))
#  define PB_CHECK_MIN(ctx,var,minv)   ((var) >= (minv))
#  define PB_CHECK_MAX(ctx,var,maxv)   ((var) <= (maxv))
#endif

#define PB_VALIDATE_PACKET_SIZE(ctx,struct_size,packet_size) do { if ((packet_size) < (struct_size)) { PB_ERROR_BUFFER_TOO_SMALL((ctx),(struct_size),(packet_size)); } else if ((packet_size) > (struct_size)) { PB_ERROR_BUFFER_TOO_BIG((ctx),(struct_size),(packet_size)); } } while(0)

#ifdef PB_HAS_FILTER
#  define PB_LOG_INVALID_OPCODE(ctx) do { PB_FILTER_CALL_ERROR((ctx),"invalid_opcode"); } while(0)
#  define PB_LOG_INVALID_HEADER(ctx) do { PB_FILTER_CALL_ERROR((ctx),"invalid_header"); } while(0)
#else
#  define PB_LOG_INVALID_OPCODE(ctx) do { } while(0)
#  define PB_LOG_INVALID_HEADER(ctx) do { } while(0)
#endif

#endif
