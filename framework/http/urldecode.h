//
// SPDX-FileCopyrightText: 2016 Abe Fehr
// SPDX-License-Identifier: MIT
//

// https://github.com/abejfehr/URLDecode

#ifndef URLENCODE_H
#define URLENCODE_H

/*
 * Function: urlDecode
 * Purpose:  Decodes a web-encoded URL. By default, +'s are converted to spaces.
 * Input:    const char* str - the URL to decode
 * Output:   char* - the decoded URL
 */
char *urlDecode(const char *str);

#endif
