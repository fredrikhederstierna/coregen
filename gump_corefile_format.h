#ifndef _GUMP_COREFILE_FORMAT_H_
#define _GUMP_COREFILE_FORMAT_H_

/*
  GUMP corefile format (RIFF)

  The corefile is composed of one main corefile header followed by a variable
  number of sections, each containing of either registers and memory data.

  There is also a meta section that describes the current firmware built to
  match the corefile. The format follows the generic RIFF file formatting.

  Each section is composed of a standard RIFF section header followed by data
  and is required to begin on a 4-byte aligned address.

  The length field in the section headers specify the actual length
  of the following data, and shall exclude the length of the header
  and any trailing padding before the next corefile section.

  The 'size' field in the main RIFF file header is different and shall include
  both the main header and trailing padding.

  Defined RIFF section types:

  "META" - section header followed by the corresponding elf file of the core
  "REGS" - section header followed by current registers
  "MD32" - section header followed by start/end addresses and memory data

  For more info on RIFF format see
  https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
*/

#define GUMP_COREFILE_VERSION (1)

#define GUMP_COREFILE_MAGIC_ID     "RIFF"
#define GUMP_COREFILE_MAGIC_FORMAT "GUMP"
#define GUMP_COREFILE_MAGIC_META   "META"
#define GUMP_COREFILE_MAGIC_REGS   "REGS"
#define GUMP_COREFILE_MAGIC_MEM    "MD32"

enum gump_corefile_section_e
{
  GUMP_COREFILE_SECTION_TYPE_UNDEF = 0,
  GUMP_COREFILE_SECTION_TYPE_META  = 1,
  GUMP_COREFILE_SECTION_TYPE_REGS  = 2,
  GUMP_COREFILE_SECTION_TYPE_MEM   = 3,
  GUMP_COREFILE_SECTION_TYPE_LAST
};
typedef enum gump_corefile_section_e gump_corefile_section_t;

/* RIFF main file header */
struct gump_corefile_header_s
{
  uint8_t  id[4];      // RIFF file id
  uint32_t size;       // total file length _including_ this header
  uint8_t  format[4];  // RIFF format
} __attribute__((packed));

/* RIFF section header */
struct gump_corefile_section_s
{
  uint8_t  type[4]; // RIFF 4-byte section/format header
  uint32_t len;     // RIFF section data length _excluding_ this header
} __attribute__((packed));

/* Contains meta info that binds this core to a specific elf */
struct gump_corefile_section_meta_s
{
  uint32_t version;

  uint8_t  device_serial[16];
  uint32_t device_type;
  uint32_t device_model;
  uint32_t device_manufacturer;

  uint8_t  fw_version_id[16];

  uint32_t fw_ver_major;
  uint32_t fw_ver_minor;
  uint32_t fw_ver_patch;
  uint32_t fw_ver_test;

  uint32_t hw_rev[4];
  uint32_t sw_rev[4];
  uint32_t mech_rev[4];
  uint32_t variant[4];

  uint8_t  build_string[128];

} __attribute__((packed));

/* Contains info on registers at corefile generation */
struct gump_corefile_section_registers_s
{
  uint32_t version;

  union {
    // This struct is based on CrashCatcher for Cortex-M.
    struct {
      // from CrashCatcherStackedRegisters:
      // This structure contains the integer registers that are automatically
      // stacked by Cortex-M processor when it enters an exception handler.
      uint32_t r0;
      uint32_t r1;
      uint32_t r2;
      uint32_t r3;
      uint32_t r12;
      uint32_t lr;
      uint32_t pc;
      uint32_t psr;
      // The following floating point registers are only stacked when
      // the LR_FLOAT bit is set in exceptionLR.
      uint32_t floats[16];
      uint32_t fpscr;
      uint32_t reserved; // keeps 8-byte alignment
      // from CrashCatcherExceptionRegisters:
      // This structure is filled in by the Hard Fault exception handler
      // (or unit test) and then passed in as a parameter to CrashCatcher_Entry().
      uint32_t msp;
      uint32_t psp;
      uint32_t exceptionPSR;
      uint32_t r4;
      uint32_t r5;
      uint32_t r6;
      uint32_t r7;
      uint32_t r8;
      uint32_t r9;
      uint32_t r10;
      uint32_t r11;
      uint32_t exceptionLR;
    } arm_regs;
    // ..more architectures could possibly be added here..

    // Raw core registers
    uint32_t regs[38];
  }; // union

} __attribute__((packed));

/* Contains info on memory contents at corefile generation */
struct gump_corefile_section_memory_s
{
  uint32_t version;

  uint32_t start_address;
  uint32_t end_address;
  // after this follows memory data
} __attribute__((packed));

#endif /* _GUMP_COREFILE_FORMAT_H_ */
