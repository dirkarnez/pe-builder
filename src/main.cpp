#include <iostream>
#include <Windows.h>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>
#include <iterator>

#include "pe.h"
#include "pebuilder.h"

using namespace std;

int main()
{
    PE p = PE::create("John")
               .lives()
               .at("123 London Road")
               .with_postcode("SW1 1GB")
               .in("London")
               .works()
               .with("PragmaSoft")
               .as_a("Consultant")
               .earning("10e6");

    cout << p << endl;

    cout << sizeof(IMAGE_DOS_HEADER) << endl;
    return EXIT_SUCCESS;
}