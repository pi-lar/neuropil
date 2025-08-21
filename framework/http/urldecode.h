//
// SPDX-FileCopyrightText: 2016 Abe Fehr
// SPDX-License-Identifier: MIT
//

// https://github.com/abejfehr/URLDecode

#ifndef URLENCODE_H
#define URLENCODE_H

#include <stdlib.h>

/*
 * Function: urlDecode
 * Purpose:  Decodes a web-encoded URL. By default, +'s are converted to spaces.
 * Input:    const char* str - the URL to decode
 * Input:    const size_t len - the length of the URL string
 * Output:   char* - the decoded URL
 */
char *urlDecode(const char *str, const size_t len);

#endif
