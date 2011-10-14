#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "houdini.h"

#define ESCAPE_GROW_FACTOR(x) (((x) * 12) / 10) /* this is very scientific, yes */

/**
 * According to the OWASP rules:
 *
 * & --> &amp;
 * < --> &lt;
 * > --> &gt;
 * " --> &quot;
 * ' --> &#x27;     &apos; is not recommended
 * / --> &#x2F;     forward slash is included as it helps end an XML entity
 *
 */
static const char *LOOKUP_CODES[] = {
	"", /* reserved: use literal single character */
	"", /* reserved: Invalid UTF-8 / escaped CP1252 character */
	"", /* reserved: 2 character UTF-8 */
	"", /* reserved: 3 character UTF-8 */
	"", /* reserved: 4 character UTF-8 */
	"", /* reserved: 5 character UTF-8 */
	"", /* reserved: 6 character UTF-8 */
	"*",
	"&quot;",
	"&amp;",
	"&#39;",
	"&#47;",
	"&lt;",
	"&gt;",
	/* CP1252 to UTF-8 convertions */
	"&#8364;", /* 128: euro sign */
	"&#8218;", /* 130: single low-9 quotation mark */
	"&#402;",  /* 131: latin small letter f with hook */
	"&#8222;", /* 132: double low-9 quotation mark */
	"&#8230;", /* 133: horizontal ellipsis */
	"&#8224;", /* 134: dagger */
	"&#8225;", /* 135: double dagger */
	"&#710;",  /* 136: modifier letter circumflex accent */
	"&#8240;", /* 137: per mille sign */
	"&#352;",  /* 138: latin capital letter s with caron */
	"&#8249;", /* 139: single left-pointing angle quotation mark */
	"&#338;",  /* 140: latin capital ligature oe */
	"&#381;",  /* 142: latin capital letter z with caron */
	"&#8216;", /* 145: left single quotation mark */
	"&#8217;", /* 146: right single quotation mark */
	"&#8220;", /* 147: left double quotation mark */
	"&#8221;", /* 148: right double quotation mark */
	"&#8226;", /* 149: bullet */
	"&#8211;", /* 150: en dash */
	"&#8212;", /* 151: em dash */
	"&#732;",  /* 152: small tilde */
	"&#8482;", /* 153: trade mark sign */
	"&#353;",  /* 154: latin small letter s with caron */
	"&#8250;", /* 155: single right-pointing angle quotation mark */
	"&#339;",  /* 156: latin small ligature oe */
	"&#382;",  /* 158: latin small letter z with caron */
	"&#376;",  /* 159: latin capital letter y with diaeresis */
	/* 160-191 & 254-255 is same UTF-8 */
};

static const char UTF8_XML_LOOKUP_TABLE[] = {
	/* ASCII: 0xxxxxxx */
	7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 7, 7, 0, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	0, 0, 8, 0, 0, 0, 9, 10,0, 0, 0, 0, 0, 0, 0,11,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,12, 0,13, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

	/* Invalid UTF-8: 10xxxxxx */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,

	/* Multibyte UTF-8 */

	/* 2 bytes: 110xxxxx */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,

	/* 3 bytes: 1110xxxx */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,

	/* 4 bytes: 11110xxx */
	4, 4, 4, 4, 4, 4, 4, 4,

	/* 5 bytes: 111110xx */
	5, 5, 5, 5,

	/* 6 bytes: 1111110x */
	6, 6,

	/* Invalid UTF-8: 1111111x */
	1, 1,
};

static const char CP1252_XML_LOOKUP_TABLE[] = {
	7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 7, 7, 0, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	0, 0, 8, 0, 0, 0, 9, 10,0, 0, 0, 0, 0, 0, 0,11,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,12, 0,13, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

	/* Map to Unicode entity */
	14, 1,15,16,17,18,19,20,21,22,23,24,25, 1,26, 1,
	1, 27,28,29,30,31,32,33,34,35,36,37,38, 1,39,40,

	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

void
houdini_escape_xml_cp1252(struct buf *ob, const uint8_t *src, size_t size)
{
	size_t  i = 0, org, code;

	bufgrow(ob, ESCAPE_GROW_FACTOR(size));

	while (i < size) {
		org = i;
		while (i < size && (code = CP1252_XML_LOOKUP_TABLE[src[i]]) == 0)
			i++;

		if (i > org)
			bufput(ob, src + org, i - org);

		/* escaping */
		if (i >= size)
			break;

		if (code == 1)
			bufprintf(ob, "&#x%x;", src[i]);
		else
			bufputs(ob, LOOKUP_CODES[code]);
		i++;
	}
}

static inline void fallback(struct buf *ob, const uint8_t *src, size_t size)
{
	ob->size = 0;
	return houdini_escape_xml_cp1252(ob, src, size);
}

void
houdini_escape_xml_utf8(struct buf *ob, const uint8_t *src, size_t size, int fallback_to_cp1252)
{
	size_t  i = 0, org, code;

	bufgrow(ob, ESCAPE_GROW_FACTOR(size));

	while (i < size) {
		org = i;
		while (i < size && (code = UTF8_XML_LOOKUP_TABLE[src[i]]) == 0)
			i++;

		if (i > org)
			bufput(ob, src + org, i - org);

		/* escaping */
		if (i >= size)
			break;

		if (code < 7) { /* multibyte UTF-8 */
			unsigned int chr = src[i++];

			if (code > 1) {
				if (code > size - i) {
					/* truncated UTF-8 character */
					if (!fallback_to_cp1252) {
						bufputc(ob, '*');
						break;
					}
					return fallback(ob, src, size);
				}
				chr &= 0xff >> code;
				while (--code) {
					unsigned char byte = src[i++];
					if (fallback_to_cp1252 && (byte & 0xc0) != 0x80)
						return fallback(ob, src, size);
					chr = (chr << 6) + (byte & 0x3f);
				}
			} else if (fallback_to_cp1252) {
				return fallback(ob, src, size);
			}

			if (chr < 0x80) {
				code = UTF8_XML_LOOKUP_TABLE[chr];
				if (code)
					bufputs(ob, LOOKUP_CODES[code]);
				else
					bufputc(ob, chr);
			} else if (chr < 0xd800 ||
				   (chr >= 0xe000 && chr <= 0xfffd) ||
				   (chr >= 0x10000 && chr <= 0x10ffff))
			{
				bufprintf(ob, "&#x%x;", chr);
			} else if (fallback_to_cp1252) {
				return fallback(ob, src, size);
			} else {
				bufputc(ob, '*');
			}
		} else {
			bufputs(ob, LOOKUP_CODES[code]);
			i++;
		}
	}
}

void
houdini_escape_xml(struct buf *ob, const uint8_t *src, size_t size)
{
	return houdini_escape_xml_utf8(ob, src, size, 1);
}
