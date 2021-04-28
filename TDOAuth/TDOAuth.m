/*
 Copyright 2011 TweetDeck Inc. All rights reserved.

 Design and implementation, Max Howell, @mxcl.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY TweetDeck Inc. ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 EVENT SHALL TweetDeck Inc. OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The views and conclusions contained in the software and documentation are
 those of the authors and should not be interpreted as representing official
 policies, either expressed or implied, of TweetDeck Inc.
*/

#import "TDOAuth.h"
#import <CommonCrypto/CommonHMAC.h>
#import <OMGHTTPURLRQ/OMGUserAgent.h>

#define TDPCEN(s) \
  [((NSString *)CFURLCreateStringByAddingPercentEscapes(NULL, (__bridge CFStringRef)[s description], NULL, CFSTR("!*'();:@&=+$,/?%#[]"), kCFStringEncodingUTF8)) autorelease]

#define TDChomp(s) { \
    const NSUInteger length = [s length]; \
    if (length > 0) \
        [s deleteCharactersInRange:NSMakeRange(length - 1, 1)]; \
}

#ifndef TDOAuthURLRequestTimeout
#define TDOAuthURLRequestTimeout 30.0
#endif

static int TDOAuthUTCTimeOffset = 0;

static NSString* nonce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef s = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    return [(NSString *)s autorelease];
}

static NSString* timestamp() {
    time_t t;
    time(&t);
    mktime(gmtime(&t));
    return [NSString stringWithFormat:@"%ld", t + TDOAuthUTCTimeOffset];
}



@implementation TDOAuth
{
    NSURL *url;
    NSString *signature_secret;
    NSMutableDictionary *oAuthParams;           // these are pre-percent encoded
    NSDictionary *params;                       // these are pre-percent encoded
    NSString *method;
    NSString *unencodedHostAndPathWithoutQuery; // we keep this because NSURL drops trailing slashes and the port number
}

/**
 * dealloc
 */
- (void)dealloc {
  [oAuthParams release];
  [params release];
  [super dealloc];
}

//- (id)initWithConsumerKey:(NSString *)consumerKey
//           consumerSecret:(NSString *)consumerSecret
//              accessToken:(NSString *)accessToken
//              tokenSecret:(NSString *)tokenSecret
//{
//  oauthParams = [NSDictionary dictionaryWithObjectsAndKeys:
//                 consumerKey,  @"oauth_consumer_key",
//                 nonce(),      @"oauth_nonce",
//                 timestamp(),  @"oauth_timestamp",
//                 @"1.0",       @"oauth_version",
//                 @"PLAINTEXT", @"oauth_signature_method",
//                 accessToken,  @"oauth_token",
//                 // LEAVE accessToken last or you'll break XAuth attempts
//                 nil];
//  signature_secret = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret ?: @""];
//  return self;
//}


- (id)initWithConsumerKey:(NSString *)consumerKey
           consumerSecret:(NSString *)consumerSecret
              accessToken:(NSString *)accessToken
              tokenSecret:(NSString *)tokenSecret
         oAuthParamsExtra:(NSDictionary *)oAuthParamsExtra
{
  self = [super init];
  if (self) {
    oAuthParams = [[NSMutableDictionary alloc] init];

    [oAuthParams addEntriesFromDictionary:oAuthParamsExtra];

    [oAuthParams addEntriesFromDictionary:[NSDictionary dictionaryWithObjectsAndKeys:
                      consumerKey,  @"oauth_consumer_key",
                      nonce(),      @"oauth_nonce",
                      timestamp(),  @"oauth_timestamp",
                      @"1.0",       @"oauth_version",
                      @"PLAINTEXT", @"oauth_signature_method",
                      nil]];

    if (accessToken) {
      [oAuthParams setValue:accessToken forKey:@"oauth_token"];
    }
    
    signature_secret = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret ?: @""];
  }
  return self;
}

- (NSString *)signature {
  // With FreshBooks API we need to use PLAINTEXT signature
  return signature_secret;
}


- (NSString *)authorizationHeader {
  NSMutableString *header = [NSMutableString stringWithCapacity:512];
  [header appendString:@"OAuth "];
  for (NSString *key in oAuthParams.allKeys)
  {
      [header appendString:[key description]];
      [header appendString:@"=\""];
      [header appendString:[oAuthParams[key] description]];
      [header appendString:@"\", "];
  }
  [header appendString:@"oauth_signature=\""];
  [header appendString:TDPCEN(self.signature)];
  [header appendString:@"\""];
  return header;
}

- (NSMutableURLRequest *)request {
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url
                                                      cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                  timeoutInterval:TDOAuthURLRequestTimeout];

    [rq setValue:OMGUserAgent() forHTTPHeaderField:@"User-Agent"];
    [rq setValue:[self authorizationHeader] forHTTPHeaderField:@"Authorization"];
    [rq setValue:@"gzip" forHTTPHeaderField:@"Accept-Encoding"];
    [rq setHTTPMethod:method];
    return rq;
}

// unencodedParameters are encoded and assigned to self->params, returns encoded queryString
- (id)setParameters:(NSDictionary *)unencodedParameters {
    NSMutableString *queryString = [NSMutableString string];
    NSMutableDictionary *encodedParameters = [NSMutableDictionary new];
    for (NSString *key in unencodedParameters.allKeys)
    {
        NSString *enkey = TDPCEN(key);
        NSString *envalue = TDPCEN(unencodedParameters[key]);
        encodedParameters[enkey] = envalue;
        [queryString appendString:enkey];
        [queryString appendString:@"="];
        [queryString appendString:envalue];
        [queryString appendString:@"&"];
    }
    TDChomp(queryString);
    params = encodedParameters;
    return queryString;
}

+ (NSMutableURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                      GETParameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
{
    return [self URLRequestForPath:unencodedPathWithoutQuery
                     GETParameters:unencodedParameters
                            scheme:@"http"
                              host:host
                       consumerKey:consumerKey
                    consumerSecret:consumerSecret
                       accessToken:accessToken
                       tokenSecret:tokenSecret];
}

+ (NSMutableURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                      GETParameters:(NSDictionary *)unencodedParameters
                             scheme:(NSString *)scheme
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret;
{
    if (!host || !unencodedPathWithoutQuery)
        return nil;

  TDOAuth *oauth = [[[TDOAuth alloc] initWithConsumerKey:consumerKey
                                          consumerSecret:consumerSecret
                                             accessToken:accessToken
                                             tokenSecret:tokenSecret
                                        oAuthParamsExtra:nil] autorelease];

    // We don't use pcen as we don't want to percent encode eg. /, this is perhaps
	// not the most all encompassing solution, but in practice it seems to work
	// everywhere and means that programmer error is *much* less likely.
    NSString *encodedPathWithoutQuery = [unencodedPathWithoutQuery stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

    id path = [oauth setParameters:unencodedParameters];
    if (path) {
        [path insertString:@"?" atIndex:0];
        [path insertString:encodedPathWithoutQuery atIndex:0];
    } else {
        path = encodedPathWithoutQuery;
    }

    oauth->method = @"GET";
    oauth->unencodedHostAndPathWithoutQuery = [host.lowercaseString stringByAppendingString:unencodedPathWithoutQuery];
    oauth->url = [[[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://%@%@", scheme, host, path]] autorelease];

    return [oauth request];
}

+ (NSMutableURLRequest *)URLRequestForPath:(NSString *)unencodedPath
                            POSTParameters:(NSDictionary *)unencodedParameters
                                      host:(NSString *)host
                               consumerKey:(NSString *)consumerKey
                            consumerSecret:(NSString *)consumerSecret
                               accessToken:(NSString *)accessToken
                               tokenSecret:(NSString *)tokenSecret
                          oAuthParamsExtra:(NSDictionary *)oAuthParamsExtra
{
    if (!host || !unencodedPath)
        return nil;

  TDOAuth *oauth = [[[TDOAuth alloc] initWithConsumerKey:consumerKey
                                          consumerSecret:consumerSecret
                                             accessToken:accessToken
                                             tokenSecret:tokenSecret
                                        oAuthParamsExtra:oAuthParamsExtra] autorelease];

    oauth->unencodedHostAndPathWithoutQuery = [host.lowercaseString stringByAppendingString:unencodedPath];
    oauth->url = [[[NSURL alloc] initWithScheme:@"https" host:host path:unencodedPath] autorelease];
    oauth->method = @"POST";

    NSMutableString *postbody = [oauth setParameters:unencodedParameters];
    NSMutableURLRequest *rq = [oauth request];

    if (postbody.length) {
        [rq setHTTPBody:[postbody dataUsingEncoding:NSUTF8StringEncoding]];
        [rq setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
        [rq setValue:[NSString stringWithFormat:@"%lu", (unsigned long)rq.HTTPBody.length] forHTTPHeaderField:@"Content-Length"];
    }

  return rq;
}

+(int)utcTimeOffset
{
    return TDOAuthUTCTimeOffset;
}

+(void)setUtcTimeOffset:(int)offset
{
    TDOAuthUTCTimeOffset = offset;
}
@end
