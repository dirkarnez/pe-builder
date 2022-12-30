#pragma once
#include <iostream>
using namespace std;

class PEBuilder;

class PE
{
    std::string m_name, m_street_address, m_post_code, m_city;  // Personal Detail
    std::string m_company_name, m_position, m_annual_income;    // Employment Detail

    PE(std::string name) : m_name(name) {}

public:
    friend class PEBuilder;
    friend ostream& operator<<(ostream&  os, const PE& obj);
    static PEBuilder create(std::string name);
};
