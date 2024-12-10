#include "blake2b.h"
#include <iostream>

int main() {
    std::string input;
    std::cout << "Enter a string: ";
    std::getline(std::cin, input);
    std::string hash = Blake2b::hash(input);

    std::cout << "Blake2b Hash (512-bit): " << hash << std::endl;
    return 0;
}