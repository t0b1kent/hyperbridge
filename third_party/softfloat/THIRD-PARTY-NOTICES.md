# SoftFloat-derived component — third-party notices

Read-only donor: FEX commit fd141ed6d721d03062619e4702bca1a0c93b6dd9, External/SoftFloat-3e. This is its explicit-state SoftFloat Release3e-derived C component, not stock upstream or a FEX runtime dependency. This directory retains all104 donor files:103 byte-identical and one with the local zero-addition correction described below. Source-specific notices remain in every C/header file. The original CMakeLists.txt is provenance; the independent Makefile selects the verified74-C subset.

Distinct original copyright paragraphs (line wrapping normalized only in this companion notice):

Copyright 2017 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2015, 2016, 2017 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2015, 2017 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2017 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2015 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2015, 2016 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2018 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2015, 2016, 2018 The Regents of the University of California. All rights reserved.

Copyright 2011, 2012, 2013, 2014, 2015, 2016 The Regents of the University of California. All Rights Reserved.

The following redistribution conditions and disclaimer are identical across all103 C/header source notices; original notices remain controlling.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions, and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions, and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the University nor the names of its contributors may
    be used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS", AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE
DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Local correction in src/s_addMagsExtF80.c: canonical same-sign zeros return their signed zero before subnormal normalization, avoiding a64-bit shift by64. This six-line correction was verified by paired UBSan runs and scoped ext80 add/sub conformance in M30. Three surrounding context lines have normalized line endings. All original source notices are preserved.

The selected74-C build excludes f128_to_f16.c, f128_mulAdd.c and f128_to_ui32.c because their required helper definitions are absent from this retained fork. Those three public APIs are unavailable; their source files remain for provenance. No contributor endorsement is implied.
