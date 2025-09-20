/*
  Warnings:

  - You are about to drop the column `contactInfo` on the `Donor` table. All the data in the column will be lost.
  - You are about to drop the column `location` on the `Donor` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `Donor` table. All the data in the column will be lost.
  - Added the required column `donationLocationId` to the `Donation` table without a default value. This is not possible if the table is not empty.
  - Added the required column `donorType` to the `Donor` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Donation" DROP CONSTRAINT "Donation_donorId_fkey";

-- DropIndex
DROP INDEX "Donor_name_key";

-- AlterTable
ALTER TABLE "Donation" ADD COLUMN     "donationLocationId" INTEGER NOT NULL,
ALTER COLUMN "donorId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Donor" DROP COLUMN "contactInfo",
DROP COLUMN "location",
DROP COLUMN "name",
ADD COLUMN     "donorType" TEXT NOT NULL,
ADD COLUMN     "email" TEXT,
ADD COLUMN     "firstName" TEXT,
ADD COLUMN     "lastName" TEXT,
ADD COLUMN     "organizationName" TEXT,
ADD COLUMN     "phoneNumber" TEXT;

-- CreateTable
CREATE TABLE "DonationLocation" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "location" TEXT,
    "contactInfo" TEXT,
    "kitchenId" INTEGER NOT NULL,

    CONSTRAINT "DonationLocation_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DonationLocation_name_key" ON "DonationLocation"("name");

-- AddForeignKey
ALTER TABLE "DonationLocation" ADD CONSTRAINT "DonationLocation_kitchenId_fkey" FOREIGN KEY ("kitchenId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Donation" ADD CONSTRAINT "Donation_donationLocationId_fkey" FOREIGN KEY ("donationLocationId") REFERENCES "DonationLocation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Donation" ADD CONSTRAINT "Donation_donorId_fkey" FOREIGN KEY ("donorId") REFERENCES "Donor"("id") ON DELETE SET NULL ON UPDATE CASCADE;
