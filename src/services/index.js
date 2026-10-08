/**
 * Default service registry.
 *
 * Consumers can pass their own adapter map to the SessionManager; this is
 * the built-in set (lms joins in a later module).
 */

import { coursesService } from './courses.js';
import { lmshomeService } from './lmshome.js';
import { samadService } from './samad.js';
import { lmsService } from './lms.js';
import { foodService } from './food.js';

/** @returns {Record<string, import('./types.js').ServiceAdapter>} */
export function defaultServices() {
  return {
    [coursesService.id]: coursesService,
    [lmshomeService.id]: lmshomeService,
    [samadService.id]: samadService,
    [lmsService.id]: lmsService,
    [foodService.id]: foodService,
  };
}

export { coursesService, lmshomeService, samadService, lmsService, foodService };
