#include "session_crypto.h"

// App2/Client: accepts one session and can send updated passwords to App1.
int main(int argc, char** argv)
{
    return RunSessionApplication(false, argc, argv);
}
