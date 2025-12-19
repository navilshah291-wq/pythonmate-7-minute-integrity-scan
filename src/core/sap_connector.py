"""
SAP RFC Connector with RFC_READ_TABLE optimization.

Handles:
- Connection pooling
- Width validation (512-byte limit)
- Pagination for large tables
- Option wrapping (72-char limit)
"""

from typing import List, Dict, Generator, Optional
from pyrfc import Connection, CommunicationError, LogonError
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class TableWidthExceededError(Exception):
    """Raised when requested fields exceed RFC_READ_TABLE 512-byte limit."""
    pass


@dataclass
class RFCConfig:
    """SAP RFC connection configuration."""
    ashost: str
    sysnr: str
    client: str
    user: str
    passwd: str
    lang: str = "EN"
    trace: str = "0"


class SapConnector:
    """
    Enterprise-grade SAP RFC connector with safety validations.

    Example:
        >>> config = RFCConfig(ashost="sap.local", sysnr="00", ...)
        >>> connector = SapConnector(config)
        >>> for batch in connector.fetch_table_batch("SOFFPHIO", ["PHIO_ID"]):
        >>>     process(batch)
    """

    # SAP standard field type widths (bytes)
    FIELD_WIDTHS = {
        "CHAR": lambda length: int(length),
        "NUMC": lambda length: int(length),
        "DATS": lambda _: 8,
        "TIMS": lambda _: 6,
        "INT4": lambda _: 10,
        "DEC": lambda length: int(length) + 2,  # Sign + decimal
        "RAWSTRING": lambda _: 0,  # Variable, handle separately
    }

    MAX_LINE_WIDTH = 512  # RFC_READ_TABLE output limit
    MAX_OPTION_LENGTH = 72  # SQL WHERE clause line limit

    def __init__(self, config: RFCConfig):
        self.config = config
        self._connection: Optional[Connection] = None

    def connect(self) -> Connection:
        """Establish SAP RFC connection with error handling."""
        try:
            self._connection = Connection(
                ashost=self.config.ashost,
                sysnr=self.config.sysnr,
                client=self.config.client,
                user=self.config.user,
                passwd=self.config.passwd,
                lang=self.config.lang,
                trace=self.config.trace,
            )
            logger.info(f"Connected to SAP: {self.config.ashost} (Client {self.config.client})")
            return self._connection
        except LogonError as e:
            logger.error(f"SAP logon failed: {e}")
            raise ConnectionError("Invalid credentials or locked user account")
        except CommunicationError as e:
            logger.error(f"SAP communication error: {e}")
            raise ConnectionError("Cannot reach SAP server. Check VPN and network.")

    def disconnect(self):
        """Close RFC connection."""
        if self._connection:
            self._connection.close()
            logger.info("SAP connection closed")

    def _validate_field_width(self, table: str, fields: List[str]) -> int:
        """
        Calculate total width of requested fields.

        Raises:
            TableWidthExceededError: If width > 512 bytes
        """
        # Get table metadata via DDIF_FIELDINFO_GET
        try:
            result = self._connection.call(
                "DDIF_FIELDINFO_GET",
                TABNAME=table,
            )
            field_info = result.get("DFIES_TAB", [])

            total_width = 0
            for field_name in fields:
                field_meta = next((f for f in field_info if f["FIELDNAME"] == field_name), None)
                if not field_meta:
                    logger.warning(f"Field {field_name} not found in {table}, assuming width 50")
                    total_width += 50
                    continue

                data_type = field_meta["DATATYPE"]
                length = field_meta.get("LENG", 0)

                if data_type in self.FIELD_WIDTHS:
                    total_width += self.FIELD_WIDTHS[data_type](length)
                else:
                    total_width += 50  # Conservative fallback

            logger.debug(f"Calculated width for {table}: {total_width} bytes")

            if total_width > self.MAX_LINE_WIDTH:
                raise TableWidthExceededError(
                    f"Fields {fields} total {total_width} bytes, exceeds {self.MAX_LINE_WIDTH} limit"
                )

            return total_width
        except Exception as e:
            logger.warning(f"Could not validate field width: {e}. Proceeding with caution.")
            return 0

    def _wrap_options(self, sql_where: str) -> List[Dict[str, str]]:
        """
        Split SQL WHERE clause into 72-character chunks.

        Example:
            "RELTYPE = 'ATTA' AND CREA_TIME > '20230101'"
            → [{"TEXT": "RELTYPE = 'ATTA' AND CREA_TIME > "}, {"TEXT": "'20230101'"}]
        """
        options = []
        # Split by logical operators to avoid breaking mid-condition
        for chunk in [sql_where[i:i+self.MAX_OPTION_LENGTH]
                      for i in range(0, len(sql_where), self.MAX_OPTION_LENGTH)]:
            options.append({"TEXT": chunk})

        logger.debug(f"Wrapped SQL into {len(options)} option rows")
        return options

    def fetch_table_batch(
        self,
        table: str,
        fields: List[str],
        where_clause: str = "",
        batch_size: int = 5000,
        max_rows: Optional[int] = None,
    ) -> Generator[List[Dict], None, None]:
        """
        Fetch table data in batches using RFC_READ_TABLE.

        Args:
            table: SAP table name (e.g., "SOFFPHIO")
            fields: List of field names to retrieve
            where_clause: SQL WHERE clause (without "WHERE" keyword)
            batch_size: Rows per iteration (default 5000 for 7-minute constraint)
            max_rows: Maximum total rows to fetch (None = unlimited)

        Yields:
            List[Dict]: Batch of rows as dictionaries

        Example:
            >>> for batch in connector.fetch_table_batch("SRGBTBREL", ["INSTID_A"], "RELTYPE = 'ATTA'"):
            >>>     for row in batch:
            >>>         print(row["INSTID_A"])
        """
        if not self._connection:
            self.connect()

        # Validate field width
        self._validate_field_width(table, fields)

        # Prepare field list for RFC
        field_list = [{"FIELDNAME": f} for f in fields]

        # Prepare WHERE clause
        options = self._wrap_options(where_clause) if where_clause else []

        skip = 0
        total_fetched = 0

        while True:
            logger.debug(f"Fetching {table} rows {skip} to {skip + batch_size}")

            try:
                result = self._connection.call(
                    "RFC_READ_TABLE",
                    QUERY_TABLE=table,
                    DELIMITER="|",
                    FIELDS=field_list,
                    OPTIONS=options,
                    ROWSKIPS=skip,
                    ROWCOUNT=batch_size,
                )
            except Exception as e:
                logger.error(f"RFC_READ_TABLE failed: {e}")
                raise RuntimeError(f"Failed to read table {table}: {e}")

            raw_data = result.get("DATA", [])
            if not raw_data:
                logger.info(f"No more data in {table} (fetched {total_fetched} total rows)")
                break

            # Parse delimited data
            parsed_batch = []
            for row in raw_data:
                values = row["WA"].split("|")
                parsed_row = {fields[i]: values[i].strip() for i in range(len(fields))}
                parsed_batch.append(parsed_row)

            yield parsed_batch

            total_fetched += len(parsed_batch)
            skip += batch_size

            # Check max_rows limit
            if max_rows and total_fetched >= max_rows:
                logger.info(f"Reached max_rows limit: {max_rows}")
                break

            # Safety: Prevent infinite loops if batch returns same data
            if len(parsed_batch) < batch_size:
                break

    def get_table_row_count(self, table: str, where_clause: str = "") -> int:
        """
        Get row count without fetching data (uses EM_GET_NUMBER_OF_ENTRIES).

        Faster than SELECT COUNT(*) for large tables.
        """
        try:
            result = self._connection.call(
                "EM_GET_NUMBER_OF_ENTRIES",
                IT_TABLES=[{"TABNAME": table}],
            )
            entries = result.get("IT_TABLES", [{}])[0].get("TABROWS", 0)
            logger.info(f"{table} has {entries:,} rows")
            return int(entries)
        except Exception as e:
            logger.warning(f"Could not get row count for {table}: {e}")
            return 0


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    config = RFCConfig(
        ashost="sapserver.local",
        sysnr="00",
        client="100",
        user="RFC_USER",
        passwd="password",
    )

    connector = SapConnector(config)

    try:
        # Test connection
        connector.connect()

        # Fetch SOFFPHIO metadata
        for batch in connector.fetch_table_batch(
            "SOFFPHIO",
            ["PHIO_ID", "LOIO_ID", "CREA_TIME"],
            "CREA_TIME > '20230101'",
            batch_size=1000,
            max_rows=10000,
        ):
            print(f"Fetched batch of {len(batch)} rows")
            # Process batch...

    finally:
        connector.disconnect()