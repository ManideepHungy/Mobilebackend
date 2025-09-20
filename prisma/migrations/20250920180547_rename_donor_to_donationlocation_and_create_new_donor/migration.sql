/*
  Warnings:

  - You are about to alter the column `incoming_dollar_value` on the `Organization` table. The data in that column could be lost. The data in that column will be cast from `DoublePrecision` to `Decimal(10,2)`.
  - A unique constraint covering the columns `[donationId,categoryId]` on the table `DonationItem` will be added. If there are existing duplicate values, this will fail.

*/
-- DropForeignKey
ALTER TABLE "Donation" DROP CONSTRAINT "Donation_shiftId_fkey";

-- AlterTable
ALTER TABLE "Donation" ALTER COLUMN "shiftId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "mealsvalue" DECIMAL(10,2) DEFAULT 10,
ALTER COLUMN "incoming_dollar_value" SET DATA TYPE DECIMAL(10,2);

-- AlterTable
ALTER TABLE "RecurringShift" ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "isRecurring" BOOLEAN NOT NULL DEFAULT true,
ALTER COLUMN "dayOfWeek" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Shift" ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "recurringShiftId" INTEGER;

-- CreateTable
CREATE TABLE "ShiftRegistrationFields" (
    "id" SERIAL NOT NULL,
    "requireFirstName" BOOLEAN NOT NULL DEFAULT true,
    "requireLastName" BOOLEAN NOT NULL DEFAULT true,
    "requireEmail" BOOLEAN NOT NULL DEFAULT true,
    "requireAgeBracket" BOOLEAN NOT NULL DEFAULT false,
    "requireBirthdate" BOOLEAN NOT NULL DEFAULT false,
    "requirePronouns" BOOLEAN NOT NULL DEFAULT false,
    "requirePhone" BOOLEAN NOT NULL DEFAULT false,
    "requireAddress" BOOLEAN NOT NULL DEFAULT false,
    "requireCity" BOOLEAN NOT NULL DEFAULT false,
    "requirePostalCode" BOOLEAN NOT NULL DEFAULT false,
    "requireHomePhone" BOOLEAN NOT NULL DEFAULT false,
    "requireEmergencyContactName" BOOLEAN NOT NULL DEFAULT false,
    "requireEmergencyContactNumber" BOOLEAN NOT NULL DEFAULT false,
    "requireCommunicationPreferences" BOOLEAN NOT NULL DEFAULT false,
    "requireProfilePictureUrl" BOOLEAN NOT NULL DEFAULT false,
    "requireAllergies" BOOLEAN NOT NULL DEFAULT false,
    "requireMedicalConcerns" BOOLEAN NOT NULL DEFAULT false,
    "requirePreferredDays" BOOLEAN NOT NULL DEFAULT false,
    "requirePreferredShifts" BOOLEAN NOT NULL DEFAULT false,
    "requireFrequency" BOOLEAN NOT NULL DEFAULT false,
    "requirePreferredPrograms" BOOLEAN NOT NULL DEFAULT false,
    "requireCanCallIfShortHanded" BOOLEAN NOT NULL DEFAULT false,
    "requireSchoolWorkCommitment" BOOLEAN NOT NULL DEFAULT false,
    "requireRequiredHours" BOOLEAN NOT NULL DEFAULT false,
    "requireHowDidYouHear" BOOLEAN NOT NULL DEFAULT false,
    "requireStartDate" BOOLEAN NOT NULL DEFAULT false,
    "requireParentGuardianName" BOOLEAN NOT NULL DEFAULT false,
    "requireParentGuardianEmail" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "recurringShiftId" INTEGER NOT NULL,

    CONSTRAINT "ShiftRegistrationFields_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RoleDefaultPermission" (
    "id" SERIAL NOT NULL,
    "role" "UserRole" NOT NULL,
    "moduleId" INTEGER NOT NULL,
    "canAccess" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "RoleDefaultPermission_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ShiftRegistrationFields_recurringShiftId_key" ON "ShiftRegistrationFields"("recurringShiftId");

-- CreateIndex
CREATE UNIQUE INDEX "RoleDefaultPermission_role_moduleId_key" ON "RoleDefaultPermission"("role", "moduleId");

-- CreateIndex
CREATE UNIQUE INDEX "DonationItem_donationId_categoryId_key" ON "DonationItem"("donationId", "categoryId");

-- AddForeignKey
ALTER TABLE "Shift" ADD CONSTRAINT "Shift_recurringShiftId_fkey" FOREIGN KEY ("recurringShiftId") REFERENCES "RecurringShift"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Donation" ADD CONSTRAINT "Donation_shiftId_fkey" FOREIGN KEY ("shiftId") REFERENCES "Shift"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ShiftRegistrationFields" ADD CONSTRAINT "ShiftRegistrationFields_recurringShiftId_fkey" FOREIGN KEY ("recurringShiftId") REFERENCES "RecurringShift"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RoleDefaultPermission" ADD CONSTRAINT "RoleDefaultPermission_moduleId_fkey" FOREIGN KEY ("moduleId") REFERENCES "Module"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
