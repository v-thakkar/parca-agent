%module arguments

%{
#include "arguments.h"
%}

%rename(_bool_operator) operator bool;
%rename("%(camelcase)s") "";  // Apply camelCase renaming to everything

%include "arguments.h"
