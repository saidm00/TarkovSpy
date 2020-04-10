#ifndef NETWORK_H
#define NETWORK_H

#include "common.h"
#include "bytestream.h"
#include "world.h"

typedef enum ActionCode
{
	ACTION_CODE_SERVER_INIT      = 147,
	ACTION_CODE_WORLD_SPAWN      = 151,
	ACTION_CODE_WORLD_UNSPAWN    = 152,
	ACTION_CODE_SUBWORLD_SPAWN   = 153,
	ACTION_CODE_SUBWORLD_UNSPAWN = 154,
	ACTION_CODE_PLAYER_SPAWN     = 155,
	ACTION_CODE_PLAYER_UNSPAWN   = 156,
	ACTION_CODE_OBSERVER_SPAWN   = 157,
	ACTION_CODE_OBSERVER_UNSPAWN = 158,
	ACTION_CODE_BATTLE_EYE       = 168,
	ACTION_CODE_GAME_UPDATE      = 170,
} ActionCode;

static inline const char *ActionCodeToString(ActionCode ac)
{
	switch (ac)
	{
		case ACTION_CODE_SERVER_INIT:      return "ACTION_CODE_SERVER_INIT";
		case ACTION_CODE_WORLD_SPAWN:      return "ACTION_CODE_WORLD_SPAWN";
		case ACTION_CODE_WORLD_UNSPAWN:    return "ACTION_CODE_WORLD_UNSPAWN";
		case ACTION_CODE_SUBWORLD_SPAWN:   return "ACTION_CODE_SUBWORLD_SPAWN";
		case ACTION_CODE_SUBWORLD_UNSPAWN: return "ACTION_CODE_SUBWORLD_UNSPAWN";
		case ACTION_CODE_PLAYER_SPAWN:     return "ACTION_CODE_PLAYER_SPAWN";
		case ACTION_CODE_PLAYER_UNSPAWN:   return "ACTION_CODE_PLAYER_UNSPAWN";
		case ACTION_CODE_OBSERVER_SPAWN:   return "ACTION_CODE_OBSERVER_SPAWN";
		case ACTION_CODE_OBSERVER_UNSPAWN: return "ACTION_CODE_OBSERVER_UNSPAWN";
		case ACTION_CODE_BATTLE_EYE:       return "ACTION_CODE_BATTLE_EYE";
		case ACTION_CODE_GAME_UPDATE:      return "ACTION_CODE_GAME_UPDATE";
		default: return "UNKNOWN";
	}
}

static inline bool IsActionStringUnknown(const char *codeString)
{
	return strcmp(codeString, "UNKNOWN") == 0;
}

void ProcessActions(World *world, ByteStream *stream, uint8_t channelID, bool outbound);

#endif // NETWORK_H