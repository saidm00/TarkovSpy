#include "network.h"
#include <stdio.h>

static Observer DeserializeObserver(ByteStream *stream)
{
    Observer obs;

    return obs;
}

static void ProcessServerInit(ByteStream *stream)
{
    
}

static void ProcessWorldSpawn(ByteStream *stream)
{

}

static void ProcessWorldUnspawn(ByteStream *stream)
{

}

static void ProcessSubworldSpawn(ByteStream *stream)
{

}

static void ProcessSubworldUnspawn(ByteStream *stream)
{

}

static void ProcessPlayerSpawn(ByteStream *stream)
{
    /*
    uint32_t pid = ByteStreamReadUInt32(stream);
    uint8_t cid = ByteStreamReadUInt8(stream);
    Vector3 pos = ByteStreamReadVector3(stream);
    
    Observer obs = DeserializeObserver(stream);
*/

}

static void ProcessPlayerUnspawn(ByteStream *stream)
{

}

static void ProcessObserverSpawn(ByteStream *stream)
{

}

static void ProcessObserverUnspawn(ByteStream *stream)
{

}

static void ProcessGameUpdate(ByteStream *stream, uint8_t channelID)
{
    
}

static void ProcessGameUpdateOutbound(ByteStream *stream, uint8_t channelID)
{

}

void ProcessActions(ByteStream *stream, uint8_t channelID, bool outbound)
{
    uint16_t head = 0;

    while (head < stream->len)
    {
        uint16_t len = ByteStreamReadUInt16(stream);
        ActionCode ac = (ActionCode)ByteStreamReadUInt16(stream);

        if (outbound)
        {
            // Only care about 170 for outbound local player updates.
            if (ac == ACTION_CODE_GAME_UPDATE)
            {
                // Process game update outbound
                ProcessGameUpdateOutbound(stream, channelID);
            }
        }
        else
        {
            // TODO: Remove debug print
            printf("Processing action with code: %hx (%s)\n", ac, ActionCodeToString(ac));

            switch (ac)
            {
                case ACTION_CODE_SERVER_INIT: ProcessServerInit(stream); break;
                case ACTION_CODE_WORLD_SPAWN: ProcessWorldSpawn(stream); break;
                case ACTION_CODE_WORLD_UNSPAWN: ProcessWorldUnspawn(stream); break;
                case ACTION_CODE_SUBWORLD_SPAWN: ProcessSubworldSpawn(stream); break;
                case ACTION_CODE_SUBWORLD_UNSPAWN: ProcessSubworldUnspawn(stream); break;
                case ACTION_CODE_PLAYER_SPAWN: ProcessPlayerSpawn(stream); break;
                case ACTION_CODE_PLAYER_UNSPAWN: ProcessPlayerUnspawn(stream); break;
                case ACTION_CODE_OBSERVER_SPAWN: ProcessObserverSpawn(stream); break;
                case ACTION_CODE_OBSERVER_UNSPAWN: ProcessObserverUnspawn(stream); break;
                case ACTION_CODE_BATTLE_EYE: break; // Ignored
                case ACTION_CODE_GAME_UPDATE: ProcessGameUpdate(stream, channelID); break;
            }
        }

        head += len + 2 * sizeof(uint16_t);
        ByteStreamSeek(stream, head);
    }
}
