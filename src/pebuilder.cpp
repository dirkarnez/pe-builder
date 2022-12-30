#include "pebuilder.h"

PEBuilder&  PEBuilder::lives() { return *this; }

PEBuilder&  PEBuilder::works() { return *this; }

PEBuilder&  PEBuilder::with(string company_name) {
    pe.m_company_name = company_name; 
    return *this;
}

PEBuilder&  PEBuilder::as_a(string position) {
    pe.m_position = position; 
    return *this;
}

PEBuilder&  PEBuilder::earning(string annual_income) {
    pe.m_annual_income = annual_income; 
    return *this;
}

PEBuilder&  PEBuilder::at(std::string street_address) {
    pe.m_street_address = street_address; 
    return *this;
}

PEBuilder&  PEBuilder::with_postcode(std::string post_code) {
    pe.m_post_code = post_code; 
    return *this;
}

PEBuilder&  PEBuilder::in(std::string city) {
    pe.m_city = city; 
    return *this;
}