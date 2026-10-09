#include "session_crypto.h"

// App1/Menu: starts the session, sends passwords, and receives updates.
int main(int argc, char** argv)
{
    return RunSessionApplication(true, argc, argv);
}
