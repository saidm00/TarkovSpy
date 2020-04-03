#ifndef UNET_H
#define UNET_H

#include <winsock2.h>
#include <math.h>

#include <string.h>
#include <stdlib.h>

#include <stdbool.h>
#include <stdint.h>

//#include "common.h"

/* Unet.h: Header for packet information (Message, net, etc) */

/* System Request flags */
typedef enum UNETSystemRequest
{
    UNET_SYSTEM_REQUEST_CONNECT               = 0x1, 
    UNET_SYSTEM_REQUEST_CONNECT_VIA_NET_GROUP = 0x2, 
    UNET_SYSTEM_REQUEST_DISCONNECT            = 0x3,
    UNET_SYSTEM_REQUEST_HEART_BEAT            = 0x4,
    UNET_SYSTEM_REQUEST_BROADCAST_DISCOVERY   = 0x9
}
UNETSystemRequest;

/* Contains the connection ID */
typedef struct UNETPacketBaseHeader
{
    uint16_t connectionId;
}
UNETPacketBaseHeader;

/* Struct for net packets UwU */
typedef struct UNETNetPacketHeader
{
    UNETPacketBaseHeader baseHeader;
    uint16_t packetId, sessionId;
}
UNETNetPacketHeader;

/* Struct for message packets */
typedef struct UNETNetMessageHeader
{
    uint8_t  channelId;
    uint16_t len;
}
UNETNetMessageHeader;

/* Struct for message ID */
typedef struct UNETNetMessageReliableHeader
{
    uint16_t messageId;
}
UNETNetMessageReliableHeader;

/* Struct for the ordered message ID :) */
typedef struct UNETNetMessageOrderedHeader
{
    uint8_t orderedMessageId;
}
UNETNetMessageOrderedHeader;

/* Struct for message ID for f*cked up fragmented messages :( */
typedef struct UNETNetMessageFragmentedHeader
{
    uint8_t  fragmentedMessageId;
    uint8_t  fragmentIdx;
    uint8_t  fragmentAmnt;
}
UNETNetMessageFragmentedHeader;

/* Struct for Acks packet info */
typedef struct UNETPacketAcks128
{
    uint16_t ackMessageId;
    uint32_t acks[4];
}
UNETPacketAcks128;

/* Decode packet base header */
inline void UNETDecodePacketBaseHeader(UNETPacketBaseHeader* hdr)
{
    hdr->connectionId = ntohs(hdr->connectionId);
}

/* Decode net packet header */
inline void UNETDecodeNetPacketHeader(UNETNetPacketHeader* hdr)
{
    hdr->packetId = ntohs(hdr->packetId);
}

/* Decode net message packet header */
inline void UNETDecodeNetMessageHeader(UNETNetMessageHeader* hdr)
{
    hdr->len = ntohs(hdr->len);
}

/* Decode _reliable_ net message packet header */
inline void UNETDecodeNetMessageReliableHeader(UNETNetMessageReliableHeader* hdr)
{
    hdr->messageId = ntohs(hdr->messageId);
}

/* Decode connection id */
inline uint16_t UNETDecodeConnectionId(void* packet)
{
    UNETPacketBaseHeader* packet_hdr = (UNETPacketBaseHeader *) (packet);
    UNETDecodePacketBaseHeader(packet_hdr);
    return packet_hdr->connectionId;
}

/* Error codes */
typedef enum UNETNetError
{
    UNET_NET_ERROR_OK = 0x0,
    UNET_NET_ERROR_WRONG_HOST,
    UNET_NET_ERROR_WRONG_CONNECTION,
    UNET_NET_ERROR_WRONG_CHANNEL,
    UNET_NET_ERROR_NO_RESOURCES,
    UNET_NET_ERROR_BAD_MESSAGE,
    UNET_NET_ERROR_TIMEOUT,
    UNET_NET_ERROR_MESSAGE_TOO_LONG,
    UNET_NET_ERROR_WRONG_OPERATION,
    UNET_NET_ERROR_VERSION_MISMATCH,
    UNET_NET_ERROR_CRC_MISMATCH,
    UNET_NET_ERROR_DNS_FAILURE,
    UNET_NET_ERROR_USAGE_ERROR,
    UNET_NET_ERROR_LAST_ERROR
}
UNETNetError;

/* Struct for m_acks data */
typedef struct UNETAcksCache
{
    bool        *m_acks;
    size_t      m_acks_size;
    uint16_t    m_head, m_tail, m_window_size;
    const char  *m_label;
}
UNETAcksCache;

/* Used to resize m_acks array, sets the new size accordingly (probably not needed, can remove later) */
inline void UNETAcksResize(UNETAcksCache *cache, size_t size)
{
    cache->m_acks = (bool *) realloc(cache->m_acks, size);    
    cache->m_acks_size = size;
}

/* Returns size of m_acks (probably not needed, can remove later) */
inline size_t UNETAcksSize(UNETAcksCache *cache)
{
    return cache->m_acks_size;
}

/* Inits Acks packet info */
inline void UNETAcksCacheInit(UNETAcksCache *cache, const char *label)
{
    cache->m_acks = (bool *) calloc(0x10000, sizeof(bool));
 
    cache->m_window_size = (UNETAcksSize(cache) / 2) - 1;
 
    cache->m_head = cache->m_window_size - 1;
    cache->m_tail = 1;
 
    cache->m_label = label;
}

/* Read acks error message */
inline bool UNETAcksReadMessage(UNETAcksCache *cache, uint16_t message_id)
{
    int max_distance = (int) UNETAcksSize(cache);
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
            cache->m_acks[cache->m_tail] = false;
            cache->m_tail = (cache->m_tail + 1) % UNETAcksSize(cache);
            cache->m_head = (cache->m_head + 1) % UNETAcksSize(cache);
        }
    }

    bool acked = cache->m_acks[message_id];
    if (!acked)
    {
        cache->m_acks[message_id] = true;
    }
    
    return !acked;
}

/* Delimiter tokens for messages (i think) */
typedef enum UNETMessageDelimeter
{
    UNET_MESSAGE_DELIMITER_COMBINED   = 254,
    UNET_MESSAGE_DELIMITER_RELIABLE  = 255
}
UNETMessageDelimeter;

/* Message packet information */
typedef struct UNETMessageExtractor
{
    char*       m_Data;
    uint16_t    m_TotalLength;
    uint16_t    m_MaxChannelId;
    uint8_t     m_Error;
    uint8_t     m_ChannelId;
    uint16_t    m_MessageLength;
    uint16_t    m_FullMessageLength;
    bool        m_IsMessageCombined;
    UNETAcksCache*  m_Acks;
}
UNETMessageExtractor;

/* Various helper functions for the message packet */
char*       UNETMessageExtractor_GetMessageStart(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_Data;
}

uint16_t    UNETMessageExtractor_GetMessageLength(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_MessageLength;
}

uint8_t     UNETMessageExtractor_GetError(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_Error;
}

bool        UNETMessageExtractor_IsError(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_Error != (uint8_t) UNET_NET_ERROR_OK;
}

uint16_t    UNETMessageExtractor_GetRemainingLength(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_TotalLength;
}

uint8_t     UNETMessageExtractor_GetChannelId(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_ChannelId;
}

uint16_t    UNETMessageExtractor_GetFullMessageLength(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_FullMessageLength;
}

bool        UNETMessageExtractor_IsMessageCombined(UNETMessageExtractor *m_ext_base)
{
    return m_ext_base->m_IsMessageCombined;
}

/* TO-DO: Document helper functions for IntelliSense */

/* Inits the packet info */
inline void UNETMessageExtractor_Init(UNETMessageExtractor *m_ext_base, char* data, uint16_t totalLength, uint8_t maxChannelId)
{
    m_ext_base->m_Data = data;
    m_ext_base->m_TotalLength = totalLength;
    m_ext_base->m_MaxChannelId = maxChannelId;
    m_ext_base->m_Error = (uint8_t) UNET_NET_ERROR_OK; // hehe "cock" 
    m_ext_base->m_ChannelId = 0xFF;
    m_ext_base->m_MessageLength = 0;
    m_ext_base->m_FullMessageLength = 0;
    m_ext_base->m_IsMessageCombined = false;
}

/* Checks if message channel ID is valid */
inline bool UNETMessageExtractor_CheckIsChannelValid(UNETMessageExtractor *m_ext_base)
{
    if(m_ext_base->m_ChannelId > m_ext_base->m_MaxChannelId)
    {
        m_ext_base->m_Error = (uint8_t) UNET_NET_ERROR_BAD_MESSAGE;
        return false;
    }
    return true;
}

/* Checks if message length is valid */
inline bool UNETMessageExtractor_CheckIsLengthValid(UNETMessageExtractor *m_ext_base)
{
    if(m_ext_base->m_TotalLength > m_ext_base->m_MessageLength)
    {
        m_ext_base->m_Error = (uint8_t) UNET_NET_ERROR_BAD_MESSAGE;
        return false;
    }
    return true;
}

/* Prototypes for commonly used functions (At least one of these are called in three of the four function definitions below) */
inline bool UNETMessageExtractor_GetNextMessage(UNETMessageExtractor *m_ext_base);
inline bool UNETMessageExtractor_ExtractMessageHeader(UNETMessageExtractor *m_ext);
inline bool UNETMessageExtractor_ExtractMessageLength(UNETMessageExtractor *m_ext_base);
inline bool UNETMessageExtractor_ExtractMessage(UNETMessageExtractor *m_ext_base);

/* Gets next message from message packet */
inline bool UNETMessageExtractor_GetNextMessage(UNETMessageExtractor *m_ext_base)
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
        m_ext_base->m_Error = (uint8_t) UNET_NET_ERROR_BAD_MESSAGE;
        return false;
    }
    
    m_ext_base->m_ChannelId = *m_ext_base->m_Data;
    
    if (m_ext_base->m_ChannelId == (uint8_t)UNET_MESSAGE_DELIMITER_RELIABLE )
    {
        UNETMessageExtractor_ExtractMessageHeader(m_ext_base);
        UNETNetMessageReliableHeader* hr = (UNETNetMessageReliableHeader *) (m_ext_base->m_Data);
        UNETDecodeNetMessageReliableHeader(hr);
        if (!UNETAcksReadMessage(m_ext_base->m_Acks, hr->messageId))
        {
            return UNETMessageExtractor_GetNextMessage(m_ext_base);
        }
        m_ext_base->m_Data += sizeof(UNETNetMessageReliableHeader);
        m_ext_base->m_TotalLength -= sizeof(UNETNetMessageReliableHeader);
        m_ext_base->m_MessageLength = 0;
        return UNETMessageExtractor_GetNextMessage(m_ext_base);
    }
    else if (m_ext_base->m_ChannelId == UNET_MESSAGE_DELIMITER_COMBINED)
    {
           ++m_ext_base->m_Data;
           --m_ext_base->m_TotalLength;
           ++m_ext_base->m_FullMessageLength;
           
           m_ext_base->m_IsMessageCombined = true;
           return UNETMessageExtractor_ExtractMessage(m_ext_base);
    }
    
    if (!UNETMessageExtractor_CheckIsChannelValid(m_ext_base))
        return false;
    
    return UNETMessageExtractor_ExtractMessage(m_ext_base);    
}

/* Extracts header of message packet */
inline bool UNETMessageExtractor_ExtractMessageHeader(UNETMessageExtractor *m_ext_base)
{
    m_ext_base->m_ChannelId = *(m_ext_base->m_Data);
    
    ++(m_ext_base->m_Data);
    --(m_ext_base->m_TotalLength);
    ++(m_ext_base->m_FullMessageLength);
    
    return UNETMessageExtractor_ExtractMessageLength(m_ext_base);
}

/* Fetches message length from message packet */
inline bool UNETMessageExtractor_ExtractMessageLength(UNETMessageExtractor *m_ext_base)
{
    uint8_t highByte = *(m_ext_base->m_Data);
    if (highByte & 0x80)
    {
        if (m_ext_base->m_TotalLength < 2)
        {
            m_ext_base->m_Error = (uint8_t) UNET_NET_ERROR_BAD_MESSAGE;
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
inline bool UNETMessageExtractor_ExtractMessage(UNETMessageExtractor *m_ext_base)
{
    if (m_ext_base->m_TotalLength < 2)
    {
        m_ext_base->m_Error = (uint8_t) UNET_NET_ERROR_BAD_MESSAGE;
        return false;
    }
    
    if (!UNETMessageExtractor_ExtractMessageHeader(m_ext_base))
        return false;

    if (!UNETMessageExtractor_CheckIsLengthValid(m_ext_base))
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