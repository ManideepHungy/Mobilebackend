/*
  Warnings:

  - Added the required column `kitchenId` to the `Donor` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Donor" ADD COLUMN     "kitchenId" INTEGER NOT NULL;

-- AddForeignKey
ALTER TABLE "Donor" ADD CONSTRAINT "Donor_kitchenId_fkey" FOREIGN KEY ("kitchenId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
