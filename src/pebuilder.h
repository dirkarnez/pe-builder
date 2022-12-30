#pragma once
#include "pe.h"

class PEBuilder
{
    PE pe;

public:
    PEBuilder(string name) : pe(name) {}

    operator PE() const { return move(pe); }

    PEBuilder&  lives();
    PEBuilder&  at(std::string street_address);
    PEBuilder&  with_postcode(std::string post_code);
    PEBuilder&  in(std::string city);
    PEBuilder&  works();
    PEBuilder&  with(string company_name);
    PEBuilder&  as_a(string position);
    PEBuilder&  earning(string annual_income);

    
};