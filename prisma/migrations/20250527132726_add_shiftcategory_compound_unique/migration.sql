/*
  Warnings:

  - A unique constraint covering the columns `[name,organizationId]` on the table `ShiftCategory` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "ShiftCategory_name_organizationId_key" ON "ShiftCategory"("name", "organizationId");
