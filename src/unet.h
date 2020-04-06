#ifndef UNET_H
#define UNET_H

#include "common.h"

#include "bytestream.h"

//#include "common.h"

/* Unet.h: Header for packet information (Message, net, etc) */

/* System Request flags */
typedef enum NetSystemRequest
{
    NET_SYSTEM_REQUEST_CONNECT               = 0x1, 
    NET_SYSTEM_REQUEST_CONNECT_VIA_NET_GROUP = 0x2, 
    NET_SYSTEM_REQUEST_DISCONNECT            = 0x3,
    NET_SYSTEM_REQUEST_HEART_BEAT            = 0x4,
    NET_SYSTEM_REQUEST_BROADCAST_DISCOVERY   = 0x9
}
NetSystemRequest;

/* Error codes */
typedef enum NetError
{
    NET_ERROR_OK = 0x0,
    NET_ERROR_WRONG_HOST,
    NET_ERROR_WRONG_CONNECTION,
    NET_ERROR_WRONG_CHANNEL,
    NET_ERROR_NO_RESOURCES,
    NET_ERROR_BAD_MESSAGE,
    NET_ERROR_TIMEOUT,
    NET_ERROR_MESSAGE_TOO_LONG,
    NET_ERROR_WRONG_OPERATION,
    NET_ERROR_VERSION_MISMATCH,
    NET_ERROR_CRC_MISMATCH,
    NET_ERROR_DNS_FAILURE,
    NET_ERROR_USAGE_ERROR,
    NET_ERROR_LAST_ERROR
}
NetError;

/* Struct for m_acks data */
typedef struct AcksCache
{
    bool *acks;
    size_t length;
    size_t head, tail, windowLength;
    const char *label;
}
AcksCache;

/* Used to resize m_acks array, sets the new size accordingly (probably not needed, can remove later) */
/*
inline void UNETAcksResize(UNETAcksCache *cache, size_t size)
{
    cache->m_acks = (bool *) realloc(cache->m_acks, size);    
    cache->m_acks_size = size;
}
*/

/* Returns size of m_acks (probably not needed, can remove later) */
/*
inline size_t UNETAcksSize(UNETAcksCache *cache)
{
    return cache->m_acks_size;
}
*/

/* Inits Acks packet info */
inline void InitializeAcksCache(AcksCache *cache, const char *label)
{
    cache->length = 65536;
    cache->acks = calloc(cache->length, sizeof(bool));
    cache->windowLength = (cache->length / 2) - 1;
    cache->head = cache->windowLength - 1;
    cache->tail = 1;
    cache->label = label;
}

/* Read acks error message */
inline bool AcksReadMessage(AcksCache *cache, uint16_t messageID)
{
    size_t maxDistance = cache->length;
    size_t rawDistance = (size_t) llabs((int64_t)messageID - (int64_t)cache->head);
    size_t distance = (rawDistance < (maxDistance / 2)) ? rawDistance : maxDistance - rawDistance;
    
    /* Out of window */
    if (distance > cache->windowLength)
    {
        return false;
    }
    
    if (messageID < cache->tail || messageID > cache->head)
    {
        /* TO-DO: "this is suboptimal, could use a second queue of packets to reset instead" --ucectoplasm
        Maybe replace this later down the line??????? */
        for (size_t i = 0; i < distance; ++i)
        {
            cache->acks[cache->tail] = false;
            cache->tail = (cache->tail + 1) % cache->length;
            cache->head = (cache->head + 1) % cache->length;
        }
    }

    bool acked = cache->acks[messageID];
    if (!acked)
    {
        cache->acks[messageID] = true;
    }
    
    return !acked;
}

/* Delimiter tokens for messages (i think) */
typedef enum MessageDelimeter
{
    MESSAGE_DELIMITER_COMBINED = 254,
    MESSAGE_DELIMITER_RELIABLE = 255
} MessageDelimeter;

/* Message packet information */
typedef struct MessageExtractor
{
    AcksCache *acks;
    uint8_t *data;
    uint16_t totalLength;
    uint16_t maxChannelID;
    uint8_t error;
    uint8_t channelID;
    uint16_t messageLength;
    uint16_t fullMessageLength;
    bool isMessageCombined;
}
MessageExtractor;

bool DidMessageExtractorError(MessageExtractor *messageExtractor)
{
    return messageExtractor->error != NET_ERROR_OK;
}

// Creates and initializes a MessageExtractor which holds state for parsing messages
inline MessageExtractor CreateMessageExtractor(ByteStream *stream, uint16_t maxChannelID, AcksCache *acks)
{
    MessageExtractor messageExtractor;

    messageExtractor.acks = acks;
    messageExtractor.data = ByteStreamHeadAddr(stream);
    messageExtractor.totalLength = ByteStreamRemaining(stream);
    messageExtractor.maxChannelID = maxChannelID;
    messageExtractor.error = NET_ERROR_OK;
    messageExtractor.channelID = 255;
    messageExtractor.messageLength = 0;
    messageExtractor.fullMessageLength = 0;
    messageExtractor.isMessageCombined = false;
    
    return messageExtractor;
}

// Checks if message channelID is valid
inline bool MessageExtractorIsChannelValid(MessageExtractor *messageExtractor)
{
    if(messageExtractor->channelID > messageExtractor->maxChannelID)
    {
        messageExtractor->error = NET_ERROR_BAD_MESSAGE;
        return false;
    }

    return true;
}

/* Checks if message length is valid */
inline bool MessageExtractorIsLengthValid(MessageExtractor *messageExtractor)
{
    if(messageExtractor->totalLength < messageExtractor->messageLength)
    {
        messageExtractor->error = NET_ERROR_BAD_MESSAGE;
        return false;
    }
    return true;
}


inline bool MessageExtractorGetChannelID(MessageExtractor *messageExtractor)
{
    return messageExtractor->channelID;
}

inline uint16_t MessageExtractorGetMessageLength(MessageExtractor *messageExtractor)
{
    return messageExtractor->messageLength;
}

inline uint8_t *MessageExtractorGetMessageStart(MessageExtractor *messageExtractor)
{
    return messageExtractor->data;
}


/* Prototypes for commonly used functions (At least one of these are called in three of the four function definitions below) */
inline bool MessageExtractorGetNextMessage(MessageExtractor *messageExtractor);
inline bool MessageExtractorExtractMessageHeader(MessageExtractor *messageExtractor);
inline bool MessageExtractorExtractMessageLength(MessageExtractor *messageExtractor);
//inline bool MessageExtractorGetMessageStart(MessageExtractor *messageExtractor);
inline bool MessageExtractorExtractMessage(MessageExtractor *messageExtractor);

/* Gets next message from message packet */
inline bool MessageExtractorGetNextMessage(MessageExtractor *messageExtractor)
{
    printf("len: %hu, %hu\n", messageExtractor->messageLength, messageExtractor->totalLength);
    messageExtractor->isMessageCombined = false;
    messageExtractor->data += messageExtractor->messageLength;
    messageExtractor->totalLength -= messageExtractor->messageLength;
    messageExtractor->fullMessageLength = 0;

    if (messageExtractor->totalLength == 0)
        return false;

    if (messageExtractor->totalLength < 2)
    {
        messageExtractor->error = (uint8_t)NET_ERROR_BAD_MESSAGE;
        return false;
    }

    messageExtractor->channelID = *messageExtractor->data;
    if (messageExtractor->channelID == (uint8_t)MESSAGE_DELIMITER_RELIABLE)
    {
        printf("Cum 0\n");
        MessageExtractorExtractMessageHeader(messageExtractor);

        NetMessageReliableHeader* hr = (NetMessageReliableHeader*)messageExtractor->data;
        hr->messageID = ntohs(hr->messageID);

        if (!AcksReadMessage(messageExtractor->acks, hr->messageID))
        {
            printf("Cum 1\n");
            return MessageExtractorGetNextMessage(messageExtractor);
        }
        messageExtractor->data += sizeof(NetMessageReliableHeader);
        messageExtractor->totalLength -= sizeof(NetMessageReliableHeader);
        messageExtractor->messageLength = 0;
        printf("Cum 2\n");
        return MessageExtractorGetNextMessage(messageExtractor);
    }
    else if (messageExtractor->channelID == (uint8_t)MESSAGE_DELIMITER_COMBINED)
    {
        printf("Cum 3\n");
        
        ++messageExtractor->data;
        --messageExtractor->totalLength;
        ++messageExtractor->fullMessageLength;
        messageExtractor->isMessageCombined = true;
        return MessageExtractorExtractMessage(messageExtractor);
    }

    printf("Cum 4\n");

    if (!MessageExtractorIsChannelValid(messageExtractor))
        return false;

    printf("Cum 5\n");
    return MessageExtractorExtractMessage(messageExtractor); 
}

/* Extracts header of message packet */
inline bool MessageExtractorExtractMessageHeader(MessageExtractor *messageExtractor)
{
    messageExtractor->channelID = *messageExtractor->data;
    
    ++messageExtractor->data;
    --messageExtractor->totalLength;
    ++messageExtractor->fullMessageLength;
    
    return MessageExtractorExtractMessageLength(messageExtractor);
}

/* Fetches message length from message packet */
inline bool MessageExtractorExtractMessageLength(MessageExtractor *messageExtractor)
{
    uint8_t highByte = *messageExtractor->data;
    if (highByte & 0x80)
    {
        if (messageExtractor->totalLength < 2)
        {
            messageExtractor->error = NET_ERROR_BAD_MESSAGE;
            return false;
        }

        messageExtractor->messageLength = ((highByte & 0x7F) << 8) + *(messageExtractor->data + 1);
        messageExtractor->totalLength -= 2;
        messageExtractor->data += 2;
        messageExtractor->fullMessageLength += 2;
    }
    else
    {
        messageExtractor->messageLength = highByte;
        --messageExtractor->totalLength;
        ++messageExtractor->data;
        ++messageExtractor->fullMessageLength;
    }

    messageExtractor->fullMessageLength += messageExtractor->messageLength;
    return true;
}

/* Extract message from message packet */
inline bool MessageExtractorExtractMessage(MessageExtractor *messageExtractor)
{
    if (messageExtractor->totalLength < 2)
    {
        messageExtractor->error = NET_ERROR_BAD_MESSAGE;
        return false;
    }
    
    if (!MessageExtractorExtractMessageHeader(messageExtractor))
        return false;

    if (!MessageExtractorIsLengthValid(messageExtractor))
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
// grandma's backend cum recycler

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
              \__________BCC_10000___________/
brb
*/

#endif //UNET_H