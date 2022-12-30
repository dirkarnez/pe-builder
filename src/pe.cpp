
#include <iostream>
#include "pe.h"
#include "pebuilder.h"

PEBuilder PE::create(string name) { return PEBuilder{name}; }

ostream& operator<<(ostream& os, const PE& obj)
{
    return os << obj.m_name
              << std::endl
              << "lives : " << std::endl
              << "at " << obj.m_street_address
              << " with postcode " << obj.m_post_code
              << " in " << obj.m_city
              << std::endl
              << "works : " << std::endl
              << "with " << obj.m_company_name
              << " as a " << obj.m_position
              << " earning " << obj.m_annual_income;
}