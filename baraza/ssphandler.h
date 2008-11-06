#ifndef __SSP_HANDLER_INCLUDED__
#define __SSP_HANDLER_INCLUDED__
#include "ssp.h"

extern char myhostname[], mydomain[]; /* the local hostname (from config) -- used in session IDs and so forth. */
extern s2sHandler_t *imps_ssp_handler; /* the one for IMPS SSP */
#endif
