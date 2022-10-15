#include "util.h"

int main(int argc, char *argv[])
{
    op::options_description desc("All options for Alpha-ESF");
    int party;
    string path;
    string endpoint;
    int thread_num;
    desc.add_options()
        ("help", "Produce help message")
        ("build", "build ESF index")
        ("thread", op::value<int>(&thread_num)->default_value(4), "thread number of building index (default 4)")
        ("path", op::value<string>(&path), "file path")
        ("endpoint", op::value<string>(&endpoint), "ip address and port")
        ("r", op::value<int>(&party), "party ID")
        ("Ns", op::value<int>(&NX), "data size of server")
        ("Nc", op::value<int>(&NY), "data size of client")
        ("Alpha", op::value<int>(&K_IND), "alpha indistinguishablity")
        ("B", op::value<int>(&N_BLOCK), "the number of buckets");
    op::variables_map vm;
    op::store(op::parse_command_line(argc, argv, desc), vm);
    op::notify(vm);
    if (argc == 1 || vm.count("help"))
    {
        std::cout << desc << std::endl;
        return 0;
    }
    if (vm.count("build") > 0)
    {
        build_index(path, thread_num);
    }
    else
    {
        if (party == 0)
        {
            user_servive(endpoint);
        }
        else
        {
            user_client(endpoint, path);
        }
    }
    return 0;
}
