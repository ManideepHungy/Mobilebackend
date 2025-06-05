-- CreateTable
CREATE TABLE "RecurringShift" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "dayOfWeek" INTEGER NOT NULL,
    "startTime" TIMESTAMP(3) NOT NULL,
    "endTime" TIMESTAMP(3) NOT NULL,
    "shiftCategoryId" INTEGER NOT NULL,
    "location" TEXT NOT NULL,
    "slots" INTEGER NOT NULL,
    "organizationId" INTEGER NOT NULL,

    CONSTRAINT "RecurringShift_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "RecurringShift" ADD CONSTRAINT "RecurringShift_shiftCategoryId_fkey" FOREIGN KEY ("shiftCategoryId") REFERENCES "ShiftCategory"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RecurringShift" ADD CONSTRAINT "RecurringShift_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
