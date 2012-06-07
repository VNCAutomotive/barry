///
/// \file	tr1_support.h
///		C++ tr1 wrapper to switch between compiler and boost support for tr1
///

/*
    Copyright (C) 2012, RealVNC Ltd.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    See the GNU General Public License in the COPYING file at the
    root directory of this project for more details.
*/

#ifndef __TR1_SUPPORT__
#define __TR1_SUPPORT__


#if defined(WINCE)
// WinCE doesn't have any TR1 support, so use boost to provide it
#include <assert.h>
// WinCE also lacks std::abort, which is needed by boost
namespace std {
	inline void abort(void) {
		assert(false);
	}
};

#include <boost/smart_ptr.hpp>

namespace Barry {
	namespace tr1 {
		using namespace boost;
	};
};

#else

#include <tr1/memory>

namespace Barry {
	namespace tr1 {
		using namespace std::tr1;
	};
};

#endif

#endif // __TR1_SUPPORT__
