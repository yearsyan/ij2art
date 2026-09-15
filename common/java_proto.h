#pragma once
#include "art_proto.h"

#define IJ2ART_CMD_JAVA_CALL 60u
#define IJ2ART_CMD_JAVA_QUERY 61u
#define IJ2ART_CMD_JAVA_LIST 62u
#define IJ2ART_CMD_JAVA_DROP 63u

// CALL: addr=optional READY dex_id (0 selects the SDK in-memory loader),
// args[0]=0 new daemon thread / 1 main Looper, data=strict UTF-8 JSON.
// Returns retval=job_id, data=JSON snapshot; it never waits for execution.
// QUERY/DROP: addr=job_id. LIST: no arguments. All return UTF-8 JSON.
// A successful RPC means accepted/queried, not that the Java methods succeeded.
// Job states: QUEUED, RUNNING, SUCCEEDED, FAILED. Completed jobs occupy one of
// 16 slots until DROP. Running/queued jobs pin their DEX and prevent shutdown.
