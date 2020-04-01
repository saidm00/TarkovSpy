#ifndef UNET_H
#define UNET_H

#include <winsock2.h>
#include <math.h>

#include <string.h>
#include <stdlib.h>

#include <stdbool.h>
#include <stdint.h>

#include "common.h"

/* Unet.h: Header for packet information (Message, net, etc) */

/* System Request flags */
typedef enum UnetSystemRequest
{
    kConnect            = 0x1, 
    kConnectViaNetGroup = 0x2, 
    kDisconnect         = 0x3,
    kHeartbeat          = 0x4,
    kBroadcastDiscovery = 0x9
}
UnetSystemRequest;

/* Contains the connection ID */
typedef struct UnetPacketBaseHeader
{
    uint16_t connectionId;
}
UnetPacketBaseHeader;

/* Struct for net packets UwU */
typedef struct UnetNetPacketHeader
{
    UnetPacketBaseHeader baseHeader;
    uint16_t packetId, sessionId;
}
UnetNetPacketHeader;

/* Struct for message packets */
typedef struct UnetNetMessageHeader
{
    uint8_t  channelId;
    uint16_t len;
}
UnetNetMessageHeader;

/* Struct for message ID */
typedef struct UnetNetMessageReliableHeader
{
    uint16_t messageId;
}
UnetNetMessageReliableHeader;

/* Struct for the ordered message ID :) */
typedef struct UnetNetMessageOrderedHeader
{
    uint8_t orderedMessageId;
}
UnetNetMessageOrderedHeader;

/* Struct for message ID for f*cked up fragmented messages :( */
typedef struct UnetNetMessageFragmentedHeader
{
    uint8_t  fragmentedMessageId;
    uint8_t  fragmentIdx;
    uint8_t  fragmentAmnt;
}
UnetNetMessageFragmentedHeader;

/* Struct for Acks packet info */
typedef struct UnetPacketAcks128
{
    uint16_t ackMessageId;
    uint32_t acks[4];
}
UnetPacketAcks128;

/* Decode packet base header */
inline void decode_PacketBaseHeader(UnetPacketBaseHeader* hdr)
{
    hdr->connectionId = ntohs(hdr->connectionId);
}

/* Decode net packet header */
inline void decode_NetPacketHeader(UnetNetPacketHeader* hdr)
{
    hdr->packetId = ntohs(hdr->packetId);
}

/* Decode net message packet header */
inline void decode_NetMessageHeader(UnetNetMessageHeader* hdr)
{
    hdr->len = ntohs(hdr->len);
}

/* Decode _reliable_ net message packet header */
inline void decode_NetMessageReliableHeader(UnetNetMessageReliableHeader* hdr)
{
    hdr->messageId = ntohs(hdr->messageId);
}

/* Decode connection id */
uint16_t decode_ConnectionId(void* packet)
{
    /* TO-DO: "this C cast scares me :( gonna fix it later" --int_45h*/
    UnetPacketBaseHeader* packet_hdr = *(UnetPacketBaseHeader *) (packet);
    decodePacketBaseHeader(packet_hdr);
    return packet_hdr->connectionId;
}

/* Error codes */
typedef enum NetErrors
{
    kOk = 0x0,
    kWrongHost,
    kWrongConnection,
    kWrongChannel,
    kNoResources,
    kBadMessage,
    kTimeout,
    kMessageToLong,
    kWrongOperation,
    kVersionMismatch,
    kCRCMismatch,
    kDNSFailure,
    kUsageError,
    kLastError
}
NetErrors;

/* Struct for m_acks data */
typedef struct AckscockCache
{
    bool        *m_acks;
    size_t      m_acks_size;
    uint16_t    m_head, m_tail, m_window_size;
    const char  *m_label
}
AckscockCache;

/* Used to resize m_acks array, sets the new size accordingly (probably not needed, can remove later) */
inline void acks_resize(AckscockCache *cache, size_t size)
{
    cache->m_acks = (bool *) realloc(size);    
    cache->m_acks_size = size;
}

/* Returns size of m_acks (probably not needed, can remove later) */
inline size_t acks_size(AckscockCache *cache)
{
    return cache->m_acks_size;
}

/* Inits Acks packet info */
inline void AckscockCacheInit(AckscockCache *cache, const char *label)
{
    cache->m_acks = (bool *) calloc(0x10000, sizeof(bool));
 
    cache->m_window_size = (acks_size(cache) / 2) - 1;
 
    cache->m_head = m_window_size - 1;
    cache->m_tail = 1;
 
    cache->m_label = label;
}

/* Read acks error message */
bool AcksReadMessage(AckscockCache *cache, uint16_t message_id)
{
    int max_distance = (int) acks_size(cache);
    int raw_distance = abs(message_id - cache->m_head);
    int distance;
    if (raw_distance < (max_distance / 2))
    {
        distance = raw_distance;
    }
    else
    {
        distance = max_distance - raw_distance;
    } 
    
    /* Out of window */
    if (distance > cache->m_window_size)
    {
        return false;
    }
    
    if (message_id < cache->m_tail || message_id > cache->m_head)
    {
        /* TO-DO: "this is suboptimal, could use a second queue of packets to reset instead" --ucectoplasm
        Maybe replace this later down the line??????? */
        for (int i = 0; i < distance; ++i)
        {
            m_acks[cache->m_tail] = false;
            cache->m_tail = (cache->m_tail + 1) % acks_size(cache);
            cache->m_head = (cache->m_head + 1) % acks_size(cache);
        }
    }

    bool acked = m_acks[message_id];
    if (!acked)
    {
        m_acks[message_id] = true;
    }
    
    return !acked;
}

/* Delimiter tokens for messages (i think) */
typedef enum UnetMessageDelimeters
{
    kCombinedMessageDelimeter   = 254,
    kReliableMessagesDelimeter  = 255
}
UnetMessageDelimeters;

/* Message packet information */
typedef struct UnetMessageExtractorBase
{
    char*       m_Data;
    uint16_t    m_TotalLength;
    uint16_t    m_MaxChannelId;
    uint8_t     m_Error;
    uint8_t     m_ChannelId;
    uint16_t    m_MessageLength;
    uint16_t    m_FullMessageLength;
    bool        m_IsMessageCombined;
}
UnetMessageExtractorBase;

/* Various helper functions for the message packet */
char*       GetMessageStart(UnetMessageExtractorBase *m_ext_base, void)       { return m_ext_base->m_Data; }
uint16_t    GetMessageLength(UnetMessageExtractorBase *m_ext_base, void)      { return m_ext_base->m_MessageLength; }
uint8_t     GetError(UnetMessageExtractorBase *m_ext_base, void)              { return m_ext_base->m_Error; }
bool        IsError(UnetMessageExtractorBase *m_ext_base, void)               { return m_ext_base->m_Error != (uint8_t) kOk; }
uint16_t    GetRemainingLength(UnetMessageExtractorBase *m_ext_base, void)    { return m_ext_base->m_TotalLength; }
uint8_t     GetChannelId(UnetMessageExtractorBase *m_ext_base, void)          { return m_ext_base->m_ChannelId; }
uint16_t    GetFullMessageLength(UnetMessageExtractorBase *m_ext_base, void)  { return m_ext_base->m_FullMessageLength; }
bool        IsMessageCombined(UnetMessageExtractorBase *m_ext_base, void)     { return m_ext_base->m_IsMessageCombined; }

/* TO-DO: Document helper functions for IntelliSense */

/* Inits the packet info */
inline void UnetMessageExtractorBaseInit(UnetMessageExtractorBase *m_ext_base, char* data, uint16_t totalLength, uint8_t maxChannelId);
{
    m_ext_base->m_Data = data;
    m_ext_base->m_TotalLength = totalLength;
    m_ext_base->m_MaxChannelId = maxChannelId;
    m_ext_base->m_Error = (uint8_t) kOk; // hehe "cock" 
    m_ext_base->m_ChannelId = 0xFF;
    m_ext_base->m_MessageLength = 0;
    m_ext_base->m_FullMessageLength = 0;
    m_ext_base->m_IsMessageCombined = false;
}

/* Checks if message channel ID is valid */
inline bool UnetCheckIsChannelValid(UnetMessageExtractorBase *m_ext_base)
{
    if(m_ext_base->m_ChannelId > m_ext_base->m_MaxChannelId)
    {
        m_ext_base->m_Error = (uint8_t) kBadMessage;
        return false;
    }
    return true;
}

/* Checks if message length is valid */
inline bool UnetCheckIsLengthValid(UnetMessageExtractorBase *m_ext_base)
{
    if(m_ext_base->m_TotalLength > m_ext_base->m_MessageLength)
    {
        m_ext_base->m_Error = (uint8_t) kBadMessage;
        return false;
    }
    return true;
}

/* Prototypes for commonly used functions (At least one of these are called in three of the four function definitions below) */
inline bool UnetMessageExtractorBase_GetNextMessage(UnetMessageExtractorBase *m_ext_base);
inline bool UnetMessageExtractorBase_ExtractMessageHeader(UnetMessageExtractorBase *m_ext);
inline bool UnetMessageExtractorBase_ExtractMessageLength(UnetMessageExtractorBase *m_ext_base);
inline bool UnetMessageExtractorBase_ExtractMessage(UnetMessageExtractorBase *m_ext_base);

/* Gets next message from message packet */
inline bool UnetMessageExtractorBase_GetNextMessage(UnetMessageExtractorBase *m_ext_base)
{
    m_ext_base->m_IsMessageCombined = false;
    m_ext_base->m_Data += m_ext_base->m_MessageLength;
    m_ext_base->m_TotalLength -= m_ext_base->m_MessageLength;
    m_ext_base->m_FullMessageLength = 0;
    
    uint16_t totalLength = m_ext_base->m_TotalLength;

    if (totalLength == 0)
        return false;
    
    if (totalLength < 2)
    {
        m_ext_base->m_Error = (uint8_t) kBadMessage;
        return false;
    }
    
    m_ext_base->m_ChannelId = *(m_ext_base->m_Data);
    
    if (m_ext_base->m_ChannelId == (uint8_t) kReliableMessagesDelimeter)
    {
        UnetMessageExtractorBase_ExtractMessageHeader(m_ext_base);
        UnetNetMessageReliableHeader* hr = *(UnetNetMessageReliableHeader *) (m_ext_base->m_Data);
        decode(hr);
        if (!m_Acks->UnetMessageExtractorBase_ReadMessage(hr->messageId))
        {
            return UnetMessageExtractorBase_GetNextMessage(m_ext_base);
        }
        m_ext_base->m_Data += sizeof(UnetNetMessageReliableHeader);
        m_ext_base->m_TotalLength -= sizeof(UnetNetMessageReliableHeader);
        m_ext_base->m_MessageLength = 0;
        return UnetMessageExtractorBase_GetNextMessage(m_ext_base);
    }
    else if (m_ext_base->m_ChannelId == kCombinedMessageDelimeter)
    {
           ++(m_ext_base->m_Data);
           --(m_ext_base->m_TotalLength);
           ++(m_ext_base->m_FullMessageLength);
           
           m_ext_base->m_IsMessageCombined = true;
           return UnetMessageExtractorBase_ExtractMessage(m_ext_base);
    }
    
    if (!UnetCheckIsChannelValid(m_ext_base))
        return false;
    
    return UnetMessageExtractorBase_ExtractMessage(m_ext_base);    
}

/* Extracts header of message packet */
inline bool UnetMessageExtractorBase_ExtractMessageHeader(UnetMessageExtractorBase *m_ext_base)
{
    m_ext_base->m_ChannelId = *(m_ext_base->m_Data);
    
    ++(m_ext_base->m_Data);
    --(m_ext_base->m_TotalLength);
    ++(m_ext_base->m_FullMessageLength);
    
    return ExtractMessageLength(m_ext_base);
}

/* Fetches message length from message packet */
inline bool UnetMessageExtractorBase_ExtractMessageLength(UnetMessageExtractorBase *m_ext_base)
{
    uint8_t highByte = *(m_ext_base->m_Data);
    if (highByte & 0x80)
    {
        if (m_ext_base->m_TotalLength < 2)
        {
            m_ext_base->m_Error = (uint8_t) kBadMessage;
            return false;
        }
        m_ext_base->m_MessageLength = ((highByte & 0x7F) << 8) + (uint8_t) * (m_ext_base->m_Data + 1);
        m_ext_base->m_TotalLength -= 2;
        m_ext_base->m_Data += 2;
        m_ext_base->m_FullMessageLength += 2;
    }
    else
    {
        m_ext_base->m_MessageLength = highByte;
        --(m_ext_base->m_TotalLength);
        ++(m_ext_base->m_Data);
        ++(m_ext_base->m_FullMessageLength);
    }
    m_ext_base->m_FullMessageLength += m_ext_base->m_MessageLength;
    return true;
}

/* Extract message from message packet */
inline bool UnetMessageExtractorBase_ExtractMessage(UnetMessageExtractorBase *m_ext_base)
{
    if (m_ext_base->m_TotalLength < 2)
    {
        m_ext_base->m_Error = (uint8_t) kBadMessage;
        return false;
    }
    
    if (!UnetMessageExtractorBase_ExtractMessageHeader(m_ext_base))
        return false;

    if (!UnetMessageExtractorBase_CheckIsLengthValid(m_ext_base))
        return false;
    
    return true;
}

/* 
"holy shit im horny as fuck
i might have been a succubus in my past life"     
    --int_45h
*/

// high as a cock in the sky
// My dad accidentally fell into a cum shaft
// My dad glazed my face with CUM
// Undercooked Baby Pig Penises
// ngl my cocc be lookin like a fat s n a c c
// _said who_?
// *drum riff*
// ight, imma pop out, sleep well my cum muffin :) UwU OwO 
// sleep tight little princess cock slayer ;O========8 

/*
   _    \    ________
    \   /   /  |   | \  << my wifes bf doing some dicc flattening on me at 3 am LUL xd
  O-|--8_____O__D   O                       yeehaw chucklefucks! big dicc marty is gonna cuck all of texas
   _/   \
        /                                                   fuck you oklahoma, you're next!
    /\_____________________________________________________________
   |And then he turned into a pickle! Funniest shit I've ever seen!|
   |_______________________________________________________________|

echo "And then he turned into a pickle! Funniest shit I've ever seen!" | cowsay -f cuckold_dick_flatten

 __________________________________________________________________
< Cock and Ball Torture from  >
 ------------------------------------------------------------------
    \
     \
    ^__^         /
    (oo)\_______/  __________________________
    (__)\ RTX ON)=(  ____|_ \__MILK_DADDY_9K_\
        ||---oo |  \ \     \_____ |          \\
        ||   ||||   ||           ||          ||
             E|_____//           \ \_________|3      ______
             E|_____/             \__________|3______|    \\
             ||                              |  _____      <~~~~    << likety lick lick 
             ||                              | /     |____//    want some natural dairy (tm) brogurt with that milk?
             ||                              ||                             
             ||                              ||
             \\______________________________//
              \__________BBC_10000___________/
*/
#endif //UNET_H