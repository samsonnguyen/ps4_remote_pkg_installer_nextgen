/*
 * Remote PKG Installer NextGen
 * Copyright (c) 2025-present AldySan and contributors.
 * Licensed under the GNU General Public License v3.0. See LICENSE for details.
 *
 * Live dashboard: status strip, transfer cards with per-item controls,
 * activity log. Dark tech theme, controller navigation.
 */
#pragma once

#include <SDL2/SDL.h>

#include <stdbool.h>

bool ui_init(SDL_Renderer* renderer);
void ui_fini(void);

/* Controller input (SDL_ControllerButtonEvent values). */
void ui_handle_button(int button);

/* Records pad activity (resets the screensaver idle timer). Returns true
 * when the screensaver was showing: that press only wakes the screen and
 * must not be acted on. */
bool ui_note_input(void);

/* Draws one dashboard frame (or the screensaver after a long idle). */
void ui_frame(SDL_Renderer* renderer);
